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
import { createNodeCompoundProgram } from "sigma/rendering";

import { createNodeBorderProgram } from "@sigma/node-border";

const NodeRingProgram = createNodeBorderProgram({
    borders: [
        { size: { value: 0.1, mode: "relative" }, color: { attribute: "borderColor" } },
        { size: { fill: true }, color: { attribute: "pictogramColor" } },
    ],
});

const NodePaddedImageProgram = createNodeImageProgram({
    padding: 0.3,
    size: { mode: "force", value: 256 },
    correctCentering: true,
    keepWithinCircle: true,
});


const NodeCustomImageProgram = createNodeCompoundProgram([
    NodeRingProgram,         // border ring + white fill
    NodePaddedImageProgram,  // image on top
]);

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
  ext: "#F1E0FF",
};

const NODE_TYPES: Record<string, string> = {
    contention: "image",
    disk: "image",
    socket: "image",
    inet: "image",
    unix: "image",
    schedule: "image",
    vfs: "image",
    thread: "border",
    ext: "border",
};

const ICON_TYPES: Record<string, string> = {
    disk: diskIcon,
    contention: lockIcon,
    socket: socketIcon,
    inet: socketIcon,
    unix: socketIcon,
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

function pictogramColorFor(nodeId: string): string {
  const prefix = nodeId.split("-")[0];
  return NODE_COLORS[prefix] ?? "#fff";
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
          graph.setEdgeAttribute(edgeId, 'size', 1);
          graph.setNodeAttribute(source, 'highlighted', false);
          graph.setNodeAttribute(source, 'borderColor', "#000");
          graph.setNodeAttribute(target, 'highlighted', false);
          graph.setNodeAttribute(target, 'borderColor', "#000");
        });

        graph.setNodeAttribute(e.node, 'highlighted', true);
        graph.setNodeAttribute(e.node, 'borderColor', "#f0c807");

        const toRemove: string[] = [];
        graph.forEachEdge((edgeId) => {
          const source = graph.source(edgeId);
          const target = graph.target(edgeId);

          if (source !== e.node && target !== e.node) {
              return;
          }

          let attribs = graph.getEdgeAttributes(edgeId)
          graph.setEdgeAttribute(edgeId, 'size', 2);
          const connectedNode = source === e.node ? target : source;
          graph.setNodeAttribute(connectedNode, 'highlighted', true);
          if (attribs.type === "line") {
              graph.setEdgeAttribute(edgeId, "color", "#000");
              graph.setNodeAttribute(target, "borderColor", "#000");
              return;
          }

          if (source === e.node) {
            graph.setEdgeAttribute(edgeId, "color", "#FFA300");
            const borderColor = graph.getNodeAttribute(target, "borderColor");
            graph.setNodeAttribute(target, "borderColor", borderColor === "#0891B1" ? "#849A59" : "#FFA300");
          } else {
            graph.setEdgeAttribute(edgeId, "color", "#0891B1");
            const borderColor = graph.getNodeAttribute(source, "borderColor");
            graph.setNodeAttribute(source, "borderColor", borderColor === "#FFA300" ? "#849A59" : "#0891B1");
          }

          toRemove.push(edgeId);
        });

        toRemove.forEach((edgeId) => {
            // bring edge to front
            const source = graph.source(edgeId);
            const target = graph.target(edgeId);
            let attribs = graph.getEdgeAttributes(edgeId);
            graph.dropEdge(edgeId);
            graph.addEdgeWithKey(edgeId, source, target, attribs);
        });

        // This is required because we are modifying the graph structure
        sigma.refresh();
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
        size: id.startsWith("schedule") ? 5 : 10,
        color: "rgba(0, 0, 0, 0)",
        pictogramColor: pictogramColorFor(id),
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
          size: 1, 
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
            image: NodeCustomImageProgram,
            border: NodeRingProgram,
        },

        // defaultEdgeType: "curve", // Curved edges show relationships better
        edgeLabelSize: 10,

        nodeReducer: (_, attrs) => ({
          ...attrs,
          size: attrs.highlighted ? attrs.size * 1.2 : attrs.size,
        }),
      }}
    >
      <LoadGraph graphData={graphData} />
    </SigmaContainer>
  );
};

export default DisplayGraph;
