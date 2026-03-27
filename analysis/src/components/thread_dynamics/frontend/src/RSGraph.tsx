import { useEffect, useState } from "react";
import Graph from "graphology";
import { useSigma, SigmaContainer, useLoadGraph, useRegisterEvents } from "@react-sigma/core";
import "@react-sigma/core/lib/style.css";
import forceAtlas2 from "graphology-layout-forceatlas2";
import { EdgeCurvedArrowProgram } from "@sigma/edge-curve";
import { NodeBorderProgram } from "@sigma/node-border";
import { createNodeImageProgram } from "@sigma/node-image";

import lockIcon from '../assets/lock.svg';
import diskIcon from '../assets/disk.svg';
import socketIcon from '../assets/socket.svg';
import scheduleIcon from '../assets/schedule.svg';
import vfsIcon from '../assets/vfs.svg';

const NodePaddedImageProgram = createNodeImageProgram({
    padding: 0.1,
});

interface Edge {
  source: string;
  target: string;
  edge_type: string;
}

interface GraphData {
  nodes: string[];
  edges: Edge[];
}

const NODE_COLORS: Record<string, string> = {
  disk: "rgba(0, 0, 0, 0)",
  thread: "#ffffff",
  contention: "rgba(0, 0, 0, 0)",
  socket: "rgba(0, 0, 0, 0)",
  schedule: "rgba(0, 0, 0, 0)",
  vfs: "rgba(0, 0, 0, 0)",
};

const NODE_TYPES: Record<string, string> = {
    contention: "image",
    disk: "image",
    socket: "image",
    schedule: "image",
    vfs: "image",
    thread: "border",
};

const ICON_TYPES: Record<string, string> = {
    disk: diskIcon,
    contention: lockIcon,
    socket: socketIcon,
    schedule: scheduleIcon,
    vfs: vfsIcon,
};

function iconFor(nodeId: string): string {
  const prefix = nodeId.split("-")[0];
  return ICON_TYPES[prefix] ?? undefined;
}

function nodeTypeFor(nodeId: string): string {
  const prefix = nodeId.split("-")[0];
  return NODE_TYPES[prefix] ?? undefined;
}

function colorFor(nodeId: string): string {
  const prefix = nodeId.split("-")[0];
  return NODE_COLORS[prefix] ?? "#999999";
}

export const LoadGraph = ({ graphData }: { graphData: GraphData }) => {
  const loadGraph = useLoadGraph();
  const registerEvents = useRegisterEvents();
  const sigma = useSigma();
  const [draggedNode, setDraggedNode] = useState<string | null>(null);

  useEffect(() => {
    // Register the drag and drop events
    registerEvents({
      // On mouse down on a node, we enable the dragging mode
      downNode: (e) => {
        setDraggedNode(e.node);
        const graph = sigma.getGraph();
        document.body.style.cursor = 'grabbing';


        // TODO: Naive implementation to deselect all nodes
        graph.forEachEdge((edgeId) => {
          const source = graph.source(edgeId);
          const target = graph.target(edgeId);
          graph.setEdgeAttribute(edgeId, 'color', "#cccccc");
          graph.setEdgeAttribute(edgeId, 'size', 1.5);
          graph.setNodeAttribute(source, 'highlighted', false);
          graph.setNodeAttribute(target, 'highlighted', false);
        });

        graph.setNodeAttribute(e.node, 'highlighted', true);
        graph.forEachEdge((edgeId) => {
          const source = graph.source(edgeId);
          const target = graph.target(edgeId);
          const edge = graph.getEdgeAttributes(edgeId);
          
          if (source === e.node || target === e.node) {
            if (edge.type !== "line") {
                graph.setEdgeAttribute(edgeId, 'color', source === e.node ? "#9333ea" : "#0891b1" );
            } else {
                graph.setEdgeAttribute(edgeId, 'color', "#000000");
            }
            graph.setEdgeAttribute(edgeId, 'size', 2);
            const connectedNode = source === e.node ? target : source;
            graph.setNodeAttribute(connectedNode, 'highlighted', true);
          }
        });
      },
      
      // On mouse move, if the drag mode is enabled, we change the position of the draggedNode
      mousemovebody: (e) => {
        if (!draggedNode) return;
        
        // Get new position of node in graph coordinates
        const pos = sigma.viewportToGraph(e);
        sigma.getGraph().setNodeAttribute(draggedNode, 'x', pos.x);
        sigma.getGraph().setNodeAttribute(draggedNode, 'y', pos.y);

        // Prevent sigma to move camera
        e.preventSigmaDefault();
        e.original.preventDefault();
        e.original.stopPropagation();
      },
      
      // On mouse up, we reset the dragging mode
      mouseup: () => {
        if (draggedNode) {
          setDraggedNode(null);
          // sigma.getGraph().setNodeAttribute(draggedNode, 'highlighted', false);
          document.body.style.cursor = 'default';
        }
      },
      
      // Disable the autoscale at the first down interaction
      mousedown: () => {
        if (!sigma.getCustomBBox()) sigma.setCustomBBox(sigma.getBBox());
      },
      
      // Change cursor on hover
      enterNode: (e) => {
        if (!draggedNode) {
          document.body.style.cursor = 'grab';
        }

        const graph = sigma.getGraph();
        graph.setNodeAttribute(e.node, 'label', e.node);
      },
      
      leaveNode: (e) => {
        if (!draggedNode) {
          document.body.style.cursor = 'default';
        }

        const graph = sigma.getGraph();
        graph.setNodeAttribute(e.node, 'label', undefined);
      }
    });

    return () => {
      document.body.style.cursor = 'default';
    };
  }, [registerEvents, sigma, draggedNode]);

  useEffect(() => {
    if (!graphData?.nodes?.length) return;

    const graph = new Graph({ multi: false, type: "directed" });

    graphData.nodes.forEach((id) => {
      const attributes = {
        label: undefined,
        size: 10,
        color: colorFor(id),
        borderColor: "#000000",
        borderSize: 1,
        type: nodeTypeFor(id),
        image: iconFor(id),
        x: Math.random(),
        y: Math.random(),
        hightlighted: false,
      };
      graph.addNode(id, attributes);
    });

    graphData.edges.forEach(({ source, target, edge_type }) => {
      if (!graph.hasEdge(source, target)) {
        graph.addEdge(source, target, { 
          size: 1.5, 
          color: "#cccccc",
          type: edge_type === "directed" ? "curvedArrow" : "line",
        });
      }
    });

    forceAtlas2.assign(graph, {
      iterations: 150,
      settings: {
        gravity: 1,
        scalingRatio: 2,
        slowDown: 10,
        barnesHutOptimize: true,
        barnesHutTheta: 0.5,
      },
    });

    loadGraph(graph);
  }, [loadGraph, graphData]);

  return null;
};

export const DisplayGraph = ({ graphData }: { graphData: GraphData }) => {
  return (
    <SigmaContainer
      style={{ background: "white", width: "800px", }}
      settings={{
        renderEdgeLabels: false,
        defaultEdgeColor: "#cccccc",
        edgeProgramClasses: {
          curvedArrow: EdgeCurvedArrowProgram,
        },
        nodeProgramClasses: {
            image: NodePaddedImageProgram,
            border: NodeBorderProgram,
        },

        // defaultEdgeType: "curve", // Curved edges show relationships better
        edgeLabelSize: 10,

        nodeReducer: (_, attrs) => ({
          ...attrs,
          size: attrs.highlighted ? attrs.size * 1.2 : attrs.size,
          // borderSize: attrs.highlighted ? 2 : 0,
          // borderColor: "#000000",
        }),
      }}
    >
      <LoadGraph graphData={graphData} />
    </SigmaContainer>
  );
};

export default DisplayGraph;
