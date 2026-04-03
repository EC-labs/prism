import React, { useEffect, useState } from 'react';
import Graph from 'graphology';
import {
    useSigma,
    SigmaContainer,
    useLoadGraph,
    useRegisterEvents,
} from '@react-sigma/core';
import '@react-sigma/core/lib/style.css';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { EdgeCurvedArrowProgram } from '@sigma/edge-curve';
import { createNodeImageProgram } from '@sigma/node-image';

import lockIcon from '../assets/lock.svg';
import diskIcon from '../assets/disk.svg';
import socketIcon from '../assets/socket.svg';
import scheduleIcon from '../assets/schedule.svg';
import vfsIcon from '../assets/vfs.svg';
import { createNodeCompoundProgram } from 'sigma/rendering';

import { createNodeBorderProgram } from '@sigma/node-border';

const NodeRingProgram = createNodeBorderProgram({
    borders: [
        {
            size: { value: 0.1, mode: 'relative' },
            color: { attribute: 'borderColor' },
        },
        { size: { fill: true }, color: { attribute: 'pictogramColor' } },
    ],
});

const NodePaddedImageProgram = createNodeImageProgram({
    padding: 0.3,
    size: { mode: 'force', value: 256 },
    correctCentering: true,
    keepWithinCircle: true,
});

const NodeCustomImageProgram = createNodeCompoundProgram([
    NodeRingProgram,
    NodePaddedImageProgram,
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
    ext: '#F1E0FF',
};

const NODE_TYPES: Record<string, string> = {
    contention: 'image',
    disk: 'image',
    socket: 'image',
    inet: 'image',
    unix: 'image',
    schedule: 'image',
    vfs: 'image',
    thread: 'border',
    ext: 'border',
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

function hashCode(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (Math.imul(31, hash) + str.charCodeAt(i)) | 0;
    }
    return hash;
}

function iconFor(nodeId: string): string {
    const prefix = nodeId.split('-')[0];
    return ICON_TYPES[prefix] ?? undefined;
}

function nodeTypeFor(nodeId: string): string {
    const prefix = nodeId.split('-')[0];
    return NODE_TYPES[prefix] ?? undefined;
}

function pictogramColorFor(nodeId: string): string {
    const prefix = nodeId.split('-')[0];
    return NODE_COLORS[prefix] ?? '#fff';
}

export const LoadGraph = ({
    graphData,
    setStateValue,
}: {
    graphData: GraphData;
    setStateValue: 'setStateValue';
}) => {
    const loadGraph = useLoadGraph();
    const registerEvents = useRegisterEvents();
    const sigma = useSigma();
    const [draggedNode, setDraggedNode] = useState<string | null>(null);

    useEffect(() => {
        registerEvents({
            downNode: (e) => {
                setDraggedNode(e.node);
                const graph = sigma.getGraph();
                setStateValue('request', e.node);
                document.body.style.cursor = 'grabbing';

                // TODO: Naive implementation to deselect all nodes
                graph.forEachEdge((edgeId) => {
                    const source = graph.source(edgeId);
                    const target = graph.target(edgeId);
                    graph.setEdgeAttribute(edgeId, 'color', '#cccccc');
                    graph.setEdgeAttribute(edgeId, 'size', 1);
                    graph.setNodeAttribute(source, 'highlighted', false);
                    graph.setNodeAttribute(source, 'borderColor', '#000');
                    graph.setNodeAttribute(target, 'highlighted', false);
                    graph.setNodeAttribute(target, 'borderColor', '#000');
                });

                graph.setNodeAttribute(e.node, 'highlighted', true);
                graph.setNodeAttribute(e.node, 'borderColor', '#f0c807');

                const toRemove: string[] = [];
                graph.forEachEdge((edgeId) => {
                    const source = graph.source(edgeId);
                    const target = graph.target(edgeId);

                    if (source !== e.node && target !== e.node) {
                        return;
                    }

                    let attribs = graph.getEdgeAttributes(edgeId);
                    graph.setEdgeAttribute(edgeId, 'size', 2);
                    const connectedNode = source === e.node ? target : source;
                    graph.setNodeAttribute(connectedNode, 'highlighted', true);
                    if (attribs.type === 'line') {
                        graph.setEdgeAttribute(edgeId, 'color', '#000');
                        return;
                    }

                    if (source === e.node) {
                        graph.setEdgeAttribute(edgeId, 'color', '#FFA300');
                        const borderColor = graph.getNodeAttribute(
                            target,
                            'borderColor'
                        );
                        graph.setNodeAttribute(
                            target,
                            'borderColor',
                            borderColor === '#0891B1' ? '#849A59' : '#FFA300'
                        );
                    } else {
                        graph.setEdgeAttribute(edgeId, 'color', '#0891B1');
                        const borderColor = graph.getNodeAttribute(
                            source,
                            'borderColor'
                        );
                        graph.setNodeAttribute(
                            source,
                            'borderColor',
                            borderColor === '#FFA300' ? '#849A59' : '#0891B1'
                        );
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

            mousemovebody: (e) => {
                if (!draggedNode) return;

                const pos = sigma.viewportToGraph(e);
                sigma.getGraph().setNodeAttribute(draggedNode, 'x', pos.x);
                sigma.getGraph().setNodeAttribute(draggedNode, 'y', pos.y);

                // Prevent sigma to move camera
                e.preventSigmaDefault();
                e.original.preventDefault();
                e.original.stopPropagation();
            },

            mouseup: () => {
                if (draggedNode) {
                    setDraggedNode(null);
                    document.body.style.cursor = 'default';
                }
            },

            // Disable the autoscale at the first down interaction
            mousedown: () => {
                if (!sigma.getCustomBBox())
                    sigma.setCustomBBox(sigma.getBBox());
            },

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
            },
        });

        return () => {
            document.body.style.cursor = 'default';
        };
    }, [registerEvents, sigma, draggedNode]);

    useEffect(() => {
        if (!graphData?.nodes?.length) return;

        const graph = new Graph({ multi: false, type: 'directed' });

        graphData.nodes.forEach((id) => {
            const h = hashCode(id);
            const attributes = {
                label: undefined,
                size: id.startsWith('schedule') ? 5 : 10,
                color: 'rgba(0, 0, 0, 0)',
                pictogramColor: pictogramColorFor(id),
                borderColor: '#000000',
                borderSize: 1,
                type: nodeTypeFor(id),
                image: iconFor(id),
                x: ((h & 0xffff) / 0xffff) * 2 - 1,
                y: (((h >> 16) & 0xffff) / 0xffff) * 2 - 1,
                hightlighted: false,
            };
            graph.addNode(id, attributes);
        });

        graphData.edges.forEach(({ source, target, edge_type }) => {
            if (!graph.hasEdge(source, target)) {
                graph.addEdge(source, target, {
                    size: 1,
                    color: '#cccccc',
                    type: edge_type === 'directed' ? 'curvedArrow' : 'line',
                });
            }
        });

        forceAtlas2.assign(graph, {
            iterations: 150,
            settings: {
                gravity: 5,
                scalingRatio: 0.5,
                slowDown: 10,
                barnesHutOptimize: false,
                barnesHutTheta: 0.5,
                strongGravityMode: true,
            },
        });

        loadGraph(graph);
    }, [loadGraph, graphData]);

    return null;
};

export const DisplayGraph = React.memo(
    ({
        graphData,
        setStateValue,
    }: {
        graphData: GraphData;
        setStateValue: 'setStateValue';
    }) => {
        return (
            <SigmaContainer
                style={{ background: 'white', width: '700px' }}
                settings={{
                    renderEdgeLabels: false,
                    defaultEdgeColor: '#cccccc',
                    edgeProgramClasses: {
                        curvedArrow: EdgeCurvedArrowProgram,
                    },
                    nodeProgramClasses: {
                        image: NodeCustomImageProgram,
                        border: NodeRingProgram,
                    },
                    allowInvalidContainer: true,
                    edgeLabelSize: 10,

                    nodeReducer: (_, attrs) => ({
                        ...attrs,
                        size: attrs.highlighted ? attrs.size * 1.2 : attrs.size,
                    }),
                }}
            >
                <LoadGraph
                    graphData={graphData}
                    setStateValue={setStateValue}
                />
            </SigmaContainer>
        );
    },
    (prevProps, nextProps) => {
        return (
            JSON.stringify(prevProps.graphData) ===
            JSON.stringify(nextProps.graphData)
        );
    }
);

export default DisplayGraph;
