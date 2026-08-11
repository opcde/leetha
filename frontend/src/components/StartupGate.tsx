import { useEffect, useState } from "react";
import { Radar } from "lucide-react";

/**
 * Holds the UI until the backend has finished starting.
 *
 * leetha serves the dashboard immediately and builds its fingerprint indexes
 * on a background thread, so every /api/ route returns 503 for the first
 * minute or two. Without this the app rendered anyway — empty tables, failed
 * requests and no explanation, which looks identical to a broken install.
 * `/health` has always reported readiness; the UI simply never asked.
 */
export function StartupGate({
  children,
  pollMs = 2000,
  bypass = false,
}: {
  children: React.ReactNode;
  /** Poll interval for /health. */
  pollMs?: number;
  /** Skip the gate entirely (e.g. the login route). */
  bypass?: boolean;
}) {
  const [ready, setReady] = useState(bypass);
  const [waitedMs, setWaitedMs] = useState(0);

  useEffect(() => {
    if (bypass) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const started = Date.now();

    const check = async () => {
      try {
        const res = await fetch("/health");
        const body = await res.json();
        if (!cancelled && body?.ready) {
          setReady(true);
          return;
        }
      } catch {
        // A refused connection while the server is coming up is expected;
        // keep waiting rather than reporting a failure.
      }
      if (!cancelled) {
        setWaitedMs(Date.now() - started);
        timer = setTimeout(check, pollMs);
      }
    };

    check();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [bypass, pollMs]);

  if (ready) return <>{children}</>;

  const seconds = Math.floor(waitedMs / 1000);

  return (
    <div className="flex min-h-screen items-center justify-center p-8">
      <div className="max-w-md text-center">
        <Radar
          size={40}
          className="mx-auto mb-5 animate-pulse text-muted-foreground"
          aria-hidden="true"
        />
        <h1 className="text-lg font-semibold mb-2">Leetha is starting</h1>
        <p className="text-sm text-muted-foreground leading-relaxed">
          Loading fingerprint databases. This normally takes a minute or two on
          first start; the dashboard opens on its own when it is done.
        </p>
        <p className="text-xs text-muted-foreground mt-4">
          Packet capture is already running — nothing is being missed.
        </p>
        {seconds >= 10 && (
          <p className="text-xs text-muted-foreground mt-3 tabular-nums">
            Waiting {seconds}s…
          </p>
        )}
      </div>
    </div>
  );
}
