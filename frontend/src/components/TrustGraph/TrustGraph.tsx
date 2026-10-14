import React, { useCallback, useEffect, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  NodeTypes,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { api, GraphData } from '../../services/api';

interface CertNodeData {
  label: string;
  certType: string;
  risk: string;
  expired: boolean;
  daysRemaining: number;
  color: string;
  certId: number;
  [key: string]: unknown;
}

interface CertNodeProps {
  data: CertNodeData;
  selected: boolean;
}

const TYPE_ICON: Record<string, string> = {
  root: '🏛',
  intermediate: '🔑',
  leaf: '📜',
};

function CertNode({ data, selected }: CertNodeProps) {
  const borderColor = selected ? 'var(--accent)' : data.color;
  const pulse = data.risk === 'CRITICAL' || data.expired;

  return (
    <div
      style={{
        background: '#ffffff',
        border: `2px solid ${borderColor}`,
        borderRadius: 10,
        padding: '10px 14px',
        minWidth: 160,
        maxWidth: 200,
        boxShadow: selected
          ? `0 0 16px rgba(234, 179, 8, 0.45)`
          : `0 2px 10px rgba(0,0,0,0.06)`,
        transition: 'box-shadow 0.2s, border-color 0.2s',
        animation: pulse ? 'pulse-glow 2s infinite' : undefined,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: data.color, width: 8, height: 8 }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 16 }}>{TYPE_ICON[data.certType] ?? '📄'}</span>
        <div style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px',
          color: data.color, background: `${data.color}20`,
          padding: '1px 5px', borderRadius: 4,
        }}>
          {data.certType}
        </div>
      </div>

      <div style={{
        fontSize: 11, fontWeight: 600, fontFamily: 'var(--font-mono)',
        color: 'var(--text-primary)', lineHeight: 1.3, wordBreak: 'break-word',
        marginBottom: 6,
      }}>
        {data.label}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{
          fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
          color: data.color, letterSpacing: '0.5px',
        }}>
          {data.risk}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          {data.expired ? '⚠ Expired' : `${data.daysRemaining}d`}
        </span>
      </div>

      <Handle type="source" position={Position.Bottom} style={{ background: data.color, width: 8, height: 8 }} />
    </div>
  );
}

const nodeTypes: NodeTypes = { certNode: CertNode as any };

interface Props {
  onSelectCert?: (id: number) => void;
}

export function TrustGraph({ onSelectCert }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api.graph().then((data: GraphData) => {
      setNodes(data.nodes as any);
      setEdges(data.edges as any);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [setNodes, setEdges]);

  useEffect(() => { load(); }, [load]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: any) => {
    if (onSelectCert && node.data?.certId) {
      onSelectCert(node.data.certId);
    }
  }, [onSelectCert]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
      <div style={{ textAlign: 'center' }}>
        <div className="spin" style={{ display: 'inline-block', fontSize: 28, marginBottom: 8 }}>⟳</div>
        <div>Building trust graph…</div>
      </div>
    </div>
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.3 }}
      style={{ background: 'var(--bg-0)' }}
      defaultEdgeOptions={{
        type: 'smoothstep',
        markerEnd: { type: 'arrowclosed' } as any,
      }}
    >
      <Background color="rgba(234, 179, 8, 0.15)" gap={20} />
      <Controls />
      <MiniMap
        nodeColor={(n: any) => n.data?.color ?? '#cbd5e1'}
        maskColor="rgba(241, 245, 249, 0.75)"
        style={{ right: 16, bottom: 16 }}
      />
    </ReactFlow>
  );
}
