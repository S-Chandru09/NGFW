import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import Navbar from "@/components/layout/Navbar";
import Sidebar from "@/components/layout/Sidebar";
import { navigationItems } from "@/config/navigation";
import { ThreatAlertSocketProvider } from "@/providers/ThreatAlertSocketProvider";
import { cn } from "@/utils";

function getPageTitle(pathname: string): string {
  const matchedItem = navigationItems.find((item) =>
    item.path === "/" ? pathname === "/" : pathname.startsWith(item.path),
  );

  return matchedItem?.label || "Dashboard";
}

export default function DashboardLayout() {
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);
  const location = useLocation();
  const pageTitle = getPageTitle(location.pathname);

  const closeMobileSidebar = () => setIsMobileSidebarOpen(false);
  const toggleMobileSidebar = () => setIsMobileSidebarOpen((current) => !current);

  return (
    <ThreatAlertSocketProvider>
      <div className="min-h-screen bg-slate-950 text-slate-100">
        <div className="flex min-h-screen">
          <div className="hidden lg:flex lg:shrink-0">
            <Sidebar items={navigationItems} />
          </div>

          {isMobileSidebarOpen ? (
            <button
              type="button"
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
              onClick={closeMobileSidebar}
              aria-label="Close navigation menu"
            />
          ) : null}

          <div
            className={cn(
              "fixed inset-y-0 left-0 z-50 w-64 transform transition-transform duration-300 lg:hidden",
              isMobileSidebarOpen ? "translate-x-0" : "-translate-x-full",
            )}
          >
            <Sidebar items={navigationItems} onNavigate={closeMobileSidebar} />
          </div>

          <div className="flex min-h-screen flex-1 flex-col">
            <Navbar onMenuClick={toggleMobileSidebar} title={pageTitle} />

            <main className="flex-1 overflow-y-auto">
              <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
                <Outlet />
              </div>
            </main>
          </div>
        </div>
      </div>
    </ThreatAlertSocketProvider>
  );
}
