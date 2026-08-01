import { useMemo, useRef, useState } from "react";
import type { NetworkGraphData, NetworkGraphEdge, NetworkGraphNode } from "@/types/networkGraph";
import { cn, formatBytes } from "@/utils";

interface NetworkGraphViewerProps {
  graph: NetworkGraphData;
}

interface PositionedNode extends NetworkGraphNode {
  px: number;
  py: number;
}

const SVG_WIDTH = 900;
const SVG_HEIGHT = 560;
const PADDING = 60;

function mapCoordinate(value: number) {
  return ((value + 1) / 2) * (SVG_WIDTH - PADDING * 2) + PADDING;
}

function getNodeColor(node: NetworkGraphNode) {
  if (node.is_threat) {
    return "#ef4444";
  }

  if (node.node_type === "internal") {
    return "#3b82f6";
  }

  return "#22c55e";
}

function getEdgeColor(edge: NetworkGraphEdge) {
  return edge.is_threat ? "#f87171" : "#475569";
}

export default function NetworkGraphViewer({ graph }: NetworkGraphViewerProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkGraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<NetworkGraphNode | null>(null);
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0, offsetX: 0, offsetY: 0 });

  const nodeMap = useMemo(() => {
    const map = new Map<string, PositionedNode>();

    graph.nodes.forEach((node) => {
      map.set(node.id, {
        ...node,
        px: mapCoordinate(node.x),
        py: mapCoordinate(node.y),
      });
    });

    return map;
  }, [graph.nodes]);

  const maxWeight = useMemo(() => {
    return Math.max(...graph.links.map((link) => link.weight), 1);
  }, [graph.links]);

  const handleWheel = (event: React.WheelEvent<SVGSVGElement>) => {
    event.preventDefault();
    const delta = event.deltaY > 0 ? -0.1 : 0.1;
    setScale((current) => Math.min(2.5, Math.max(0.6, current + delta)));
  };

  const handleMouseDown = (event: React.MouseEvent<SVGSVGElement>) => {
    if (event.button !== 0) {
      return;
    }

    setIsPanning(true);
    panStart.current = {
      x: event.clientX,
      y: event.clientY,
      offsetX: offset.x,
      offsetY: offset.y,
    };
  };

  const handleMouseMove = (event: React.MouseEvent<SVGSVGElement>) => {
    if (!isPanning) {
      return;
    }

    const deltaX = event.clientX - panStart.current.x;
    const deltaY = event.clientY - panStart.current.y;

    setOffset({
      x: panStart.current.offsetX + deltaX,
      y: panStart.current.offsetY + deltaY,
    });
  };

  const stopPanning = () => setIsPanning(false);

  const activeNode = hoveredNode || selectedNode;

  if (graph.nodes.length === 0) {
    return (
      <div className="flex h-[560px] items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-950/50 text-sm text-slate-500">
        No network graph data available for the selected period
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
        <span className="inline-flex items-center gap-2">
          <span className="h-3 w-3 rounded-full bg-blue-500" />
          Internal
        </span>
        <span className="inline-flex items-center gap-2">
          <span className="h-3 w-3 rounded-full bg-emerald-500" />
          External
        </span>
        <span className="inline-flex items-center gap-2">
          <span className="h-3 w-3 rounded-full bg-red-500" />
          Threat
        </span>
        <span>Scroll to zoom • Drag to pan • Click node for details</span>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/70">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
          className={cn("h-[560px] w-full touch-none", isPanning ? "cursor-grabbing" : "cursor-grab")}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={stopPanning}
          onMouseLeave={stopPanning}
        >
          <rect width={SVG_WIDTH} height={SVG_HEIGHT} fill="#020617" />

          <g transform={`translate(${offset.x} ${offset.y}) scale(${scale})`}>
            {graph.links.map((edge) => {
              const source = nodeMap.get(edge.source);
              const target = nodeMap.get(edge.target);

              if (!source || !target) {
                return null;
              }

              const strokeWidth = 1 + (edge.weight / maxWeight) * 4;

              return (
                <g key={edge.id}>
                  <line
                    x1={source.px}
                    y1={source.py}
                    x2={target.px}
                    y2={target.py}
                    stroke={getEdgeColor(edge)}
                    strokeWidth={strokeWidth}
                    strokeOpacity={0.7}
                    markerEnd="url(#arrowhead)"
                  />
                </g>
              );
            })}

            {graph.nodes.map((node) => {
              const positioned = nodeMap.get(node.id);
              if (!positioned) {
                return null;
              }

              const radius = 8 + Math.min(node.flow_count, 20) * 0.5;
              const isActive = activeNode?.id === node.id;

              return (
                <g
                  key={node.id}
                  transform={`translate(${positioned.px} ${positioned.py})`}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => setSelectedNode(node)}
                  className="cursor-pointer"
                >
                  <circle
                    r={radius + 4}
                    fill={getNodeColor(node)}
                    opacity={isActive ? 0.25 : 0.12}
                  />
                  <circle
                    r={radius}
                    fill={getNodeColor(node)}
                    stroke={isActive ? "#f8fafc" : "#0f172a"}
                    strokeWidth={isActive ? 2 : 1}
                  />
                  <text
                    y={radius + 14}
                    textAnchor="middle"
                    fill="#cbd5e1"
                    fontSize="10"
                  >
                    {node.label.length > 15 ? `${node.label.slice(0, 12)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </g>

          <defs>
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="8"
              refX="8"
              refY="4"
              orient="auto"
            >
              <polygon points="0 0, 8 4, 0 8" fill="#64748b" />
            </marker>
          </defs>
        </svg>
      </div>

      {activeNode ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h4 className="text-sm font-semibold text-white">{activeNode.ip}</h4>
              <p className="mt-1 text-xs capitalize text-slate-400">
                {activeNode.node_type} node
                {activeNode.is_threat ? " • threat detected" : ""}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setSelectedNode(null)}
              className="text-xs text-slate-500 transition hover:text-slate-300"
            >
              Clear selection
            </button>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-500">Flows</p>
              <p className="mt-1 text-sm font-medium text-white">{activeNode.flow_count}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-500">Threat Count</p>
              <p className="mt-1 text-sm font-medium text-white">{activeNode.threat_count}</p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-500">Total Bytes</p>
              <p className="mt-1 text-sm font-medium text-white">
                {formatBytes(activeNode.total_bytes)}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
              <p className="text-xs text-slate-500">NetworkX Position</p>
              <p className="mt-1 text-sm font-medium text-white">
                ({activeNode.x.toFixed(2)}, {activeNode.y.toFixed(2)})
              </p>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
