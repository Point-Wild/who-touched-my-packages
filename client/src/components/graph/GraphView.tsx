import type { EdgeTypes, NodeTypes } from '@xyflow/react';
import {
    Background,
    Controls,
    ReactFlow,
    ReactFlowProvider,
    useReactFlow
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useCallback, useEffect } from 'react';
import { CustomNode } from './CustomNode';
import { ElkEdge } from './ElkEdge';

const nodeTypes: NodeTypes = {
    custom: CustomNode,
};

const edgeTypes: EdgeTypes = {
    elk: ElkEdge,
};

export interface GraphViewProps {
    nodes: any[];
    edges: any[];
    onNodeClick?: (nodeId: string | null) => void;
    fitViewSignal?: number;
}

function FitViewEffect({ signal }: { signal?: number }) {
    const { fitView } = useReactFlow();
    useEffect(() => {
        if (signal == null || signal === 0) return;
        // Wait for nodes to be fully rendered before fitting view
        const id = setTimeout(() => {
            fitView({ 
                duration: 400, 
                padding: 0.2, 
                maxZoom: 1,
                minZoom: 0.1,
                includeHiddenNodes: false
            });
        }, 300);
        return () => clearTimeout(id);
    }, [signal, fitView]);
    return null;
}

export function GraphView({ nodes, edges, onNodeClick, fitViewSignal }: GraphViewProps) {
    const handleNodeClick = useCallback((_event: React.MouseEvent, node: any) => {
        onNodeClick?.(node.id);
    }, [onNodeClick]);

    const handlePaneClick = useCallback(() => {
        onNodeClick?.(null);
    }, [onNodeClick]);

    return (
        <div style={{ width: '100%', height: '100%' }}>
            <ReactFlowProvider>
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    nodeTypes={nodeTypes}
                    edgeTypes={edgeTypes}
                    onNodeClick={handleNodeClick}
                    onPaneClick={handlePaneClick}
                    defaultEdgeOptions={{
                        focusable: false,
                        selectable: false,
                        interactionWidth: 0
                    }}
                    nodesDraggable={false}
                    onlyRenderVisibleElements={true}
                    proOptions={{ hideAttribution: true }}
                    minZoom={0.1}
                    maxZoom={1.5}
                >
                    <FitViewEffect signal={fitViewSignal} />
                    <Background gap={16} color="var(--border-color)" />
                    <Controls />
                </ReactFlow>
            </ReactFlowProvider>
        </div>
    );
}
