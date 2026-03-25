import ELK from 'elkjs/lib/elk-api';

const elk = new ELK({
    workerUrl: new URL('elkjs/lib/elk-worker.min.js', import.meta.url).href
});

const nodeEdgeGap = "40";
const nodeNodeGap = "40";

const elkOptions = {
    'elk.algorithm': 'layered',
    'elk.direction': 'RIGHT',
    'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
    'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
    "elk.spacing.nodeNode": nodeNodeGap,
    "elk.layered.spacing.nodeNodeBetweenLayers": nodeNodeGap,
    "elk.spacing.edgeNode": nodeEdgeGap,
    "elk.layered.spacing.edgeEdgeBetweenLayers": nodeEdgeGap,
    "elk.layered.spacing.edgeNodeBetweenLayers": nodeEdgeGap,
    "elk.layered.wrapping.additionalEdgeSpacing": nodeEdgeGap,
    "elk.spacing.nodeSelfLoop": nodeEdgeGap
};

self.onmessage = async (e: MessageEvent<{
    nodes: any[];
    validEdges: any[];
}>) => {
    try {
        const { nodes: graphNodes, validEdges } = e.data;

        // If there are no edges, use a simple grid layout
        if (validEdges.length === 0) {
            const cols = Math.ceil(Math.sqrt(graphNodes.length));
            const nodeWidth = 280;
            const nodeHeight = 120;
            const spacing = 50;
            
            const layoutedNodes = graphNodes.map((node: any, index: number) => {
                const col = index % cols;
                const row = Math.floor(index / cols);
                const delay = Math.min((col * (nodeWidth + spacing)) / 1000, 1.5);
                
                return {
                    id: node.id,
                    position: {
                        x: col * (nodeWidth + spacing),
                        y: row * (nodeHeight + spacing),
                    },
                    data: node,
                    type: 'custom',
                    style: { animation: `fadeIn 0.5s ease both ${delay}s` }
                };
            });
            
            self.postMessage({
                type: 'success',
                nodes: layoutedNodes,
                edges: [],
            });
            return;
        }

        const idMap = new Map<string, string>();
        let idCounter = 0;
        const getSafeId = (realId: string) => {
            if (!idMap.has(realId)) {
                idMap.set(realId, `n${idCounter++}`);
            }
            return idMap.get(realId)!;
        };

        const nodes = graphNodes
            .sort((a, b) => a.id.localeCompare(b.id))
            .map(n => ({
                id: getSafeId(n.id),
                width: 280,
                height: 120,
                data: n,
            }));

        const edges = validEdges
            .sort((a, b) => a.source.localeCompare(b.source) || a.target.localeCompare(b.target))
            .map((e, idx) => ({
                id: `e${idx}`,
                sources: [getSafeId(e.source)],
                targets: [getSafeId(e.target)],
                data: { type: e.type }
            }));

        const graph = {
            id: 'root',
            layoutOptions: elkOptions,
            children: nodes,
            edges: edges
        };

        const edgeIndex = new Map<string, any>();
        edges.forEach((e) => edgeIndex.set(e.id, e));

        const layoutedGraph = await elk.layout(graph as any);

        const reactFlowNodes = (layoutedGraph.children || []).map((node) => {
            const delay = Math.min((node.x || 0) / 1000, 1.5);
            return {
                id: getSafeId((node as any).data.id),
                position: { x: node.x || 0, y: node.y || 0 },
                data: (node as any).data,
                type: 'custom',
                style: { animation: `fadeIn 0.5s ease both ${delay}s` }
            };
        });

        const safeReactFlowEdges = (layoutedGraph.edges || []).map((elkEdge: any) => {
            const { id, sections } = elkEdge;
            const e = edgeIndex.get(id);

            return {
                id: `reactflow-e${id}`,
                source: e.sources[0],
                target: e.targets[0],
                type: 'elk',
                animated: e.data.type === 'dev',
                style: {
                    stroke: e.data.type === 'dev' ? '#60a5fa' : 'var(--text-muted)',
                    strokeWidth: 2,
                    strokeDasharray: e.data.type === 'dev' ? '6 6' : undefined,
                    opacity: 0.6,
                },
                data: {
                    ...e.data,
                    path: sections?.[0],
                },
            };
        });

        self.postMessage({ type: 'success', nodes: reactFlowNodes, edges: safeReactFlowEdges });
    } catch (err) {
        console.error('ELK Layout Worker Error', err);
        self.postMessage({ type: 'error', error: err instanceof Error ? err.message : String(err) });
    }
};
