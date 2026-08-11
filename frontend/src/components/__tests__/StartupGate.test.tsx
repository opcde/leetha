import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { StartupGate } from "@/components/StartupGate";

/**
 * While leetha loads its fingerprint databases every /api/ route returns 503.
 * The dashboard used to render anyway: empty tables and failed requests for a
 * couple of minutes on every start, with no indication it was still starting.
 * /health has always reported readiness -- the UI just never asked.
 */
function mockHealth(sequence: Array<{ ready: boolean } | "error">) {
  let i = 0;
  return vi.fn(async () => {
    const step = sequence[Math.min(i, sequence.length - 1)] ?? { ready: false };
    i += 1;
    if (step === "error") throw new Error("connection refused");
    return { ok: true, json: async () => ({ status: "ok", ready: step.ready }) } as Response;
  });
}

describe("StartupGate", () => {
  beforeEach(() => vi.useRealTimers());
  afterEach(() => vi.restoreAllMocks());

  it("shows the starting state while the backend is not ready", async () => {
    vi.stubGlobal("fetch", mockHealth([{ ready: false }]));
    render(<StartupGate><div>dashboard</div></StartupGate>);

    expect(await screen.findByText(/starting/i)).toBeInTheDocument();
    expect(screen.queryByText("dashboard")).not.toBeInTheDocument();
  });

  it("explains why it is waiting rather than just spinning", async () => {
    vi.stubGlobal("fetch", mockHealth([{ ready: false }]));
    render(<StartupGate><div>dashboard</div></StartupGate>);

    expect(await screen.findByText(/fingerprint/i)).toBeInTheDocument();
  });

  it("renders the app once the backend reports ready", async () => {
    vi.stubGlobal("fetch", mockHealth([{ ready: true }]));
    render(<StartupGate><div>dashboard</div></StartupGate>);

    expect(await screen.findByText("dashboard")).toBeInTheDocument();
  });

  it("transitions from starting to ready without a reload", async () => {
    vi.stubGlobal("fetch", mockHealth([{ ready: false }, { ready: true }]));
    render(<StartupGate pollMs={10}><div>dashboard</div></StartupGate>);

    expect(await screen.findByText(/starting/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("dashboard")).toBeInTheDocument(),
                  { timeout: 3000 });
  });

  it("keeps waiting when /health cannot be reached", async () => {
    // A refused connection during startup is normal, not a hard failure.
    vi.stubGlobal("fetch", mockHealth(["error"]));
    render(<StartupGate pollMs={10}><div>dashboard</div></StartupGate>);

    expect(await screen.findByText(/starting/i)).toBeInTheDocument();
    expect(screen.queryByText("dashboard")).not.toBeInTheDocument();
  });

  it("never blocks the login page", async () => {
    // Signing in must stay possible while the capture engine warms up.
    vi.stubGlobal("fetch", mockHealth([{ ready: false }]));
    render(<StartupGate bypass><div>login</div></StartupGate>);

    expect(await screen.findByText("login")).toBeInTheDocument();
  });
});
