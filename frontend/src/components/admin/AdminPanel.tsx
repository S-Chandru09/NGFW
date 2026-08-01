import { useState } from "react";
import LogsPanel from "@/components/admin/LogsPanel";
import RulesPanel from "@/components/admin/RulesPanel";
import ThreatIntelligencePanel from "@/components/admin/ThreatIntelligencePanel";
import UsersPanel from "@/components/admin/UsersPanel";
import type { AdminTab } from "@/types/admin";
import { cn } from "@/utils";

const tabs: Array<{ id: AdminTab; label: string; description: string }> = [
  { id: "users", label: "Users", description: "Accounts & roles" },
  { id: "rules", label: "Rules", description: "Firewall policies" },
  { id: "logs", label: "Logs", description: "Audit trail" },
  { id: "threat-intelligence", label: "Threat Intelligence", description: "IOC database" },
];

export default function AdminPanel() {
  const [activeTab, setActiveTab] = useState<AdminTab>("users");

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white">Admin Panel</h2>
        <p className="mt-1 text-sm text-slate-400">
          Centralized management for users, firewall rules, audit logs, and threat intelligence
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-1">
        <div className="grid gap-1 sm:grid-cols-2 xl:grid-cols-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "rounded-xl px-4 py-3 text-left transition",
                activeTab === tab.id
                  ? "bg-primary-500/15 ring-1 ring-primary-500/30"
                  : "hover:bg-slate-800/60",
              )}
            >
              <p
                className={cn(
                  "text-sm font-semibold",
                  activeTab === tab.id ? "text-primary-300" : "text-slate-200",
                )}
              >
                {tab.label}
              </p>
              <p className="mt-0.5 text-xs text-slate-500">{tab.description}</p>
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 sm:p-6">
        {activeTab === "users" ? <UsersPanel /> : null}
        {activeTab === "rules" ? <RulesPanel /> : null}
        {activeTab === "logs" ? <LogsPanel /> : null}
        {activeTab === "threat-intelligence" ? <ThreatIntelligencePanel /> : null}
      </div>
    </div>
  );
}
