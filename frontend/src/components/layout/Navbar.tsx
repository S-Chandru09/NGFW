import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/utils";

interface NavbarProps {
  onMenuClick: () => void;
  title?: string;
}

export default function Navbar({ onMenuClick, title = "Dashboard" }: NavbarProps) {
  const { user, logout, isSubmitting } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);

  const initials = user?.full_name
    ? user.full_name
        .split(" ")
        .map((part) => part[0])
        .join("")
        .slice(0, 2)
        .toUpperCase()
    : user?.email?.slice(0, 2).toUpperCase() || "U";

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800 bg-slate-950/90 px-4 backdrop-blur-md sm:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onMenuClick}
          className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-slate-800 text-slate-300 transition hover:bg-slate-900 hover:text-white lg:hidden"
          aria-label="Open navigation menu"
        >
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        <div>
          <h1 className="text-lg font-semibold text-white sm:text-xl">{title}</h1>
          <p className="hidden text-xs text-slate-500 sm:block">
            AI-powered next generation firewall
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 sm:gap-4">
        <button
          type="button"
          className="hidden h-10 w-10 items-center justify-center rounded-lg border border-slate-800 text-slate-400 transition hover:bg-slate-900 hover:text-slate-200 sm:inline-flex"
          aria-label="Notifications"
        >
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6 6 0 10-12 0v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
        </button>

        <div className="relative">
          <button
            type="button"
            onClick={() => setShowUserMenu((current) => !current)}
            className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/70 px-2 py-1.5 transition hover:bg-slate-900 sm:px-3"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary-500/20 text-xs font-semibold text-primary-300">
              {initials}
            </div>
            <div className="hidden text-left sm:block">
              <p className="text-sm font-medium text-white">{user?.full_name || user?.username}</p>
              <p className="text-xs capitalize text-slate-500">{user?.role}</p>
            </div>
            <svg
              className={cn("hidden h-4 w-4 text-slate-500 transition sm:block", showUserMenu && "rotate-180")}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {showUserMenu ? (
            <>
              <button
                type="button"
                className="fixed inset-0 z-40 cursor-default"
                onClick={() => setShowUserMenu(false)}
                aria-label="Close user menu"
              />
              <div className="absolute right-0 z-50 mt-2 w-56 rounded-xl border border-slate-800 bg-slate-900 p-2 shadow-xl">
                <div className="border-b border-slate-800 px-3 py-2">
                  <p className="text-sm font-medium text-white">{user?.full_name}</p>
                  <p className="truncate text-xs text-slate-500">{user?.email}</p>
                </div>
                <button
                  type="button"
                  onClick={() => logout()}
                  disabled={isSubmitting}
                  className="mt-2 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-red-300 transition hover:bg-red-500/10 disabled:opacity-60"
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  {isSubmitting ? "Signing out..." : "Sign out"}
                </button>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </header>
  );
}
