import { FormEvent, useState } from "react";
import { useAuth } from "@/providers/AuthProvider";
import { APP_NAME } from "@/config/env";
import { cn } from "@/utils";

export default function LoginPage() {
  const { login, isSubmitting, error, clearError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    clearError();
    setFormError(null);

    if (!email.trim()) {
      setFormError("Email is required");
      return;
    }

    if (!password.trim()) {
      setFormError("Password is required");
      return;
    }

    if (password.length < 8) {
      setFormError("Password must be at least 8 characters");
      return;
    }

    try {
      await login({ email: email.trim(), password });
    } catch {
      // Error is handled in auth context
    }
  };

  const displayError = formError || error;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="grid min-h-screen lg:grid-cols-2">
        <section className="relative hidden overflow-hidden bg-gradient-to-br from-primary-900 via-slate-900 to-slate-950 lg:flex lg:flex-col lg:justify-between lg:p-12">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.25),_transparent_50%)]" />
          <div className="relative">
            <div className="inline-flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary-500/20 ring-1 ring-primary-400/30">
                <svg
                  className="h-6 w-6 text-primary-300"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.8}
                    d="M12 3l8 4v6c0 4.418-3.582 8-8 8s-8-3.582-8-8V7l8-4z"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-primary-200">Zero Trust Security</p>
                <h1 className="text-xl font-semibold text-white">{APP_NAME}</h1>
              </div>
            </div>
          </div>

          <div className="relative max-w-lg">
            <h2 className="text-4xl font-bold tracking-tight text-white">
              AI-powered threat detection for modern networks
            </h2>
            <p className="mt-4 text-base leading-7 text-slate-300">
              Monitor traffic, detect attacks in real time, and enforce zero trust
              policies from a unified next-generation firewall dashboard.
            </p>
            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              {["Real-time alerts", "ML threat scoring", "Firewall control", "Audit logging"].map(
                (feature) => (
                  <div
                    key={feature}
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200 backdrop-blur-sm"
                  >
                    {feature}
                  </div>
                ),
              )}
            </div>
          </div>

          <p className="relative text-sm text-slate-400">
            Secure access with JWT authentication and role-based permissions.
          </p>
        </section>

        <section className="flex items-center justify-center px-4 py-10 sm:px-6 lg:px-8">
          <div className="w-full max-w-md">
            <div className="mb-8 text-center lg:text-left">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs text-slate-400 lg:hidden">
                <span className="h-2 w-2 rounded-full bg-primary-500" />
                AI-NGFW Secure Login
              </div>
              <h2 className="text-3xl font-bold tracking-tight text-white">Sign in</h2>
              <p className="mt-2 text-sm text-slate-400">
                Enter your credentials to access the security dashboard.
              </p>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-2xl shadow-black/20 backdrop-blur-sm sm:p-8">
              <form className="space-y-5" onSubmit={handleSubmit} noValidate>
                {displayError ? (
                  <div
                    role="alert"
                    className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300"
                  >
                    {displayError}
                  </div>
                ) : null}

                <div>
                  <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-200">
                    Email address
                  </label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="analyst@company.com"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20"
                  />
                </div>

                <div>
                  <label
                    htmlFor="password"
                    className="mb-2 block text-sm font-medium text-slate-200"
                  >
                    Password
                  </label>
                  <div className="relative">
                    <input
                      id="password"
                      name="password"
                      type={showPassword ? "text" : "password"}
                      autoComplete="current-password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder="Enter your password"
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 pr-12 text-sm text-white outline-none transition placeholder:text-slate-500 focus:border-primary-500 focus:ring-2 focus:ring-primary-500/20"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((current) => !current)}
                      className="absolute inset-y-0 right-0 px-3 text-xs font-medium text-slate-400 transition hover:text-slate-200"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className={cn(
                    "flex w-full items-center justify-center rounded-lg bg-primary-600 px-4 py-3 text-sm font-semibold text-white transition",
                    "hover:bg-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/40",
                    "disabled:cursor-not-allowed disabled:opacity-60",
                  )}
                >
                  {isSubmitting ? (
                    <>
                      <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      Signing in...
                    </>
                  ) : (
                    "Sign in"
                  )}
                </button>
              </form>
            </div>

            <p className="mt-6 text-center text-xs text-slate-500">
              Protected by JWT authentication. Unauthorized access is monitored.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}
