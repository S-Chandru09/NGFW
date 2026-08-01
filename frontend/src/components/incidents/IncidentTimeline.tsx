import StatusBadge, { severityBadgeVariant } from "@/components/admin/StatusBadge";
import type { Incident, TimelineEvent } from "@/types/incident";
import { cn, formatDateTime } from "@/utils";

function buildTimelineEvents(incident: Incident): TimelineEvent[] {
  const events: TimelineEvent[] = [
    {
      id: `${incident.incident_id}-created`,
      timestamp: incident.created_at,
      title: "Incident Created",
      description: `Incident opened by system with status "${incident.status}"`,
      type: "created",
      severity: incident.severity,
    },
    {
      id: `${incident.incident_id}-detected`,
      timestamp: incident.detected_at,
      title: "Threat Detected",
      description: incident.threat_type
        ? `Threat type: ${incident.threat_type}`
        : "Security event detected and logged",
      type: "detected",
      severity: incident.severity,
    },
  ];

  for (const action of incident.actions_taken) {
    let title = "Action Recorded";
    let description = `Performed by ${action.actor_username}`;

    switch (action.action_type) {
      case "block_ip":
        title = "IP Blocked";
        description = `Blocked ${String(action.details.blocked_ip ?? "IP")} via firewall rule ${String(action.details.firewall_rule_name ?? "")}`;
        break;
      case "kill_session":
        title = "Session Terminated";
        description = `Killed ${Array.isArray(action.details.session_ids) ? action.details.session_ids.length : 0} session(s), revoked ${String(action.details.revoked_token_count ?? 0)} token(s)`;
        break;
      case "generate_report":
        title = "Report Generated";
        description = `Report ${String(action.details.report_id ?? "")} created`;
        break;
      case "status_change":
        title = "Status Changed";
        description = `Changed from ${String(action.details.previous_status)} to ${String(action.details.new_status)}`;
        break;
      case "note":
        title = "Analyst Note";
        description = String(action.details.note ?? "Note added");
        break;
      default:
        break;
    }

    events.push({
      id: action.action_id,
      timestamp: action.timestamp,
      title,
      description,
      type: action.action_type,
      actor: action.actor_username,
    });
  }

  if (incident.resolved_at) {
    events.push({
      id: `${incident.incident_id}-resolved`,
      timestamp: incident.resolved_at,
      title: "Incident Resolved",
      description: `Incident marked as ${incident.status}`,
      type: "resolved",
    });
  }

  return events.sort(
    (left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime(),
  );
}

function eventDotClass(type: TimelineEvent["type"]) {
  switch (type) {
    case "block_ip":
      return "bg-red-500 ring-red-500/30";
    case "kill_session":
      return "bg-amber-500 ring-amber-500/30";
    case "generate_report":
      return "bg-sky-500 ring-sky-500/30";
    case "status_change":
      return "bg-violet-500 ring-violet-500/30";
    case "resolved":
      return "bg-emerald-500 ring-emerald-500/30";
    case "detected":
      return "bg-orange-500 ring-orange-500/30";
    default:
      return "bg-primary-500 ring-primary-500/30";
  }
}

interface IncidentTimelineProps {
  incident: Incident | null;
}

export default function IncidentTimeline({ incident }: IncidentTimelineProps) {
  if (!incident) {
    return (
      <div className="flex min-h-[320px] items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/40 p-6">
        <p className="text-sm text-slate-500">Select an incident to view its response timeline</p>
      </div>
    );
  }

  const events = buildTimelineEvents(incident);

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
      <div className="flex flex-col gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-sm font-semibold text-white">{incident.title}</h3>
          <p className="mt-1 text-xs text-slate-500">
            Incident timeline · {events.length} event{events.length === 1 ? "" : "s"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge label={incident.severity} variant={severityBadgeVariant(incident.severity)} />
          <StatusBadge label={incident.status.replace("_", " ")} variant="info" />
        </div>
      </div>

      <div className="mt-6 space-y-0">
        {events.map((event, index) => (
          <div key={event.id} className="relative flex gap-4 pb-8 last:pb-0">
            {index < events.length - 1 ? (
              <span className="absolute left-[11px] top-6 h-full w-px bg-slate-800" />
            ) : null}

            <span
              className={cn(
                "relative z-10 mt-1 h-6 w-6 shrink-0 rounded-full ring-4",
                eventDotClass(event.type),
              )}
            />

            <div className="min-w-0 flex-1">
              <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-sm font-medium text-white">{event.title}</p>
                <p className="text-xs text-slate-500">{formatDateTime(event.timestamp)}</p>
              </div>
              <p className="mt-1 text-sm text-slate-400">{event.description}</p>
              {event.actor ? (
                <p className="mt-1 text-xs text-slate-500">By {event.actor}</p>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export { buildTimelineEvents };
