import { Handle, Position } from '@xyflow/react';
import { memo } from 'react';

const NODE_WIDTH = 280;
const NODE_HEIGHT = 140;

interface CustomNodeProps {
    data: {
        id: string;
        name: string;
        version: string;
        ecosystem: 'npm' | 'pypi';
        file: string;
        isDev?: boolean;
        isVulnerable?: boolean;
        isRoot?: boolean;
    };
    selected?: boolean;
}

const hiddenHandleStyle = { opacity: 0, pointerEvents: 'none' as const };

export const CustomNode = memo(function CustomNode({ data, selected }: CustomNodeProps) {
    let bgColor = 'var(--accent-blue)';
    if (data.isRoot) bgColor = 'var(--accent-emerald)';
    if (data.isVulnerable) bgColor = 'var(--critical)';

    const borderColor = selected ? 'var(--accent-blue)' : bgColor;

    return (
        <div style={{
            width: NODE_WIDTH,
            height: NODE_HEIGHT,
            background: 'var(--bg-secondary)',
            border: `3px solid ${borderColor}`,
            borderRadius: '12px',
            padding: '12px',
            boxShadow: selected ? '0 0 0 2px var(--accent-blue)' : '0 2px 8px rgba(0,0,0,0.3)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            transition: 'all 0.2s ease',
        }}>
            <Handle type="target" position={Position.Left} style={hiddenHandleStyle} />
            <Handle type="source" position={Position.Right} style={hiddenHandleStyle} />
            
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                borderBottom: `2px solid ${bgColor}`,
                paddingBottom: '8px',
            }}>
                <div style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: bgColor,
                    flexShrink: 0,
                }} />
                <div style={{
                    fontWeight: 700,
                    fontSize: '14px',
                    color: 'var(--text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }}>
                    {data.name}
                </div>
            </div>

            <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
                fontSize: '12px',
                color: 'var(--text-secondary)',
            }}>
                <div>
                    <strong>Version:</strong> <code style={{ fontSize: '11px' }}>{data.version}</code>
                </div>
                <div>
                    <strong>Ecosystem:</strong> <span style={{
                        background: data.ecosystem === 'npm' ? 'var(--accent-blue)' : 'var(--accent-emerald)',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 600,
                    }}>{data.ecosystem}</span>
                </div>
                {data.isDev && (
                    <div style={{ color: 'var(--accent-blue)' }}>
                        <strong>Dev Dependency</strong>
                    </div>
                )}
                {data.isVulnerable && (
                    <div style={{ color: 'var(--critical)', fontWeight: 600 }}>
                        ⚠️ Vulnerable
                    </div>
                )}
            </div>
        </div>
    );
});
