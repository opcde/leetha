import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Radar, CheckCircle2, RotateCcw, Eraser } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

export interface BaselineStatus {
  learning: boolean;
  first_capture_at: string | null;
  window_closed_at: string | null;
  devices_found: number;
  quiet_for_seconds: number | null;
  learning_mode: string;
  approved: number;
  unapproved: number;
  rejected: number;
}

async function fetchBaselineStatus(): Promise<BaselineStatus> {
  const res = await fetch("/api/baseline/status");
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function post(path: string) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

function humanDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function formatDate(raw: string | null): string {
  if (!raw) return "unknown";
  try {
    return new Date(raw).toLocaleString();
  } catch {
    return raw;
  }
}

/**
 * Learning-window policy.
 *
 * Alert noise used to be silenced by bulk-approving every device, which
 * recorded that a human had verified each one when nobody had looked. The
 * window handles it instead: leetha stays quiet while it is still learning the
 * network, and escalates only devices that arrive after it has.
 */
export function DiscoveryAlertingSection({
  values,
  updateField,
}: {
  values: Record<string, unknown>;
  // Matches Settings.tsx's updateField exactly; widening it to `unknown`
  // makes the two signatures incompatible.
  updateField: (key: string, value: string | number | boolean) => void;
}) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["baseline-status"],
    queryFn: fetchBaselineStatus,
    refetchInterval: 15000,
  });

  const act = async (path: string, message: (r: any) => string) => {
    setBusy(true);
    try {
      const result = await post(path);
      toast.success(message(result));
      qc.invalidateQueries({ queryKey: ["baseline-status"] });
      qc.invalidateQueries({ queryKey: ["devices"] });
    } catch {
      toast.error("Request failed");
    } finally {
      setBusy(false);
    }
  };

  const mode = (values.baseline_learning_mode as string) ?? "automatic";

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold mb-1">Discovery &amp; Alerting</h3>
        <p className="text-sm text-muted-foreground">
          Controls when a newly-seen device counts as a genuine arrival worth
          alerting on, rather than part of the network leetha is still learning.
        </p>
      </div>
      <Separator />

      {/* Live status */}
      <div className="rounded-lg border border-border bg-secondary/50 p-4">
        {isLoading || !data ? (
          <div className="text-sm text-muted-foreground">Loading status…</div>
        ) : data.learning ? (
          <div className="flex items-start gap-3">
            <Radar size={18} className="mt-0.5 text-amber-500 shrink-0" />
            <div>
              <div className="text-sm font-medium">Learning this network</div>
              <div className="text-xs text-muted-foreground mt-0.5">
                {data.devices_found} device(s) found
                {data.quiet_for_seconds !== null && (
                  <> · quiet for {humanDuration(data.quiet_for_seconds)}</>
                )}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                New devices are recorded but graded INFO. Once discovery goes
                quiet, later arrivals escalate to WARNING.
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-start gap-3">
            <CheckCircle2 size={18} className="mt-0.5 text-emerald-500 shrink-0" />
            <div>
              <div className="text-sm font-medium">
                Watching since {formatDate(data.first_capture_at)}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">
                {data.devices_found} device(s) known · learned{" "}
                {formatDate(data.window_closed_at)}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                A device that appears now is a genuine new arrival and grades
                WARNING.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Policy */}
      <div className="space-y-2">
        <label className="text-sm font-medium">Learning mode</label>
        <Select
          value={mode}
          onValueChange={(v) => updateField("baseline_learning_mode", v)}
        >
          <SelectTrigger className="max-w-md">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="automatic">
              Automatic — stop learning once discovery goes quiet
            </SelectItem>
            <SelectItem value="always_learning">
              Always learning — never escalate (assessment runs)
            </SelectItem>
            <SelectItem value="manual">
              Manual — only stop when I say so
            </SelectItem>
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          Automatic scales to the size of the network rather than to a fixed
          duration, so it suits both a short assessment and a long deployment.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-2xl">
        <div className="space-y-2">
          <label className="text-sm font-medium">Quiet period (minutes)</label>
          <input
            type="number"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={(values.baseline_quiet_period_minutes as number) ?? 30}
            onChange={(e) =>
              updateField("baseline_quiet_period_minutes", Number(e.target.value))
            }
          />
          <p className="text-xs text-muted-foreground">
            Minimum silence before the network counts as learned.
          </p>
        </div>
        <div className="space-y-2">
          <label className="text-sm font-medium">Maximum learning (days)</label>
          <input
            type="number"
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={(values.baseline_max_window_days as number) ?? 7}
            onChange={(e) =>
              updateField("baseline_max_window_days", Number(e.target.value))
            }
          />
          <p className="text-xs text-muted-foreground">
            Hard cap, so learning always ends even on a churning network.
          </p>
        </div>
      </div>

      <Separator />

      {/* Actions */}
      <div className="flex flex-wrap gap-3">
        {data?.learning ? (
          <Button
            disabled={busy}
            onClick={() =>
              act("/api/baseline/finish", () => "Learning finished")
            }
          >
            <CheckCircle2 size={16} className="mr-2" />
            Finish learning now
          </Button>
        ) : (
          <Button
            variant="outline"
            disabled={busy}
            onClick={() =>
              act("/api/baseline/restart-learning", () => "Re-entered learning")
            }
          >
            <RotateCcw size={16} className="mr-2" />
            Start learning again
          </Button>
        )}
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => {
            if (
              !confirm(
                "Revert approvals made by the old bulk 'Set baseline' button?\n\n" +
                  "Those recorded that a human had verified each device when " +
                  "nobody had reviewed them. Devices you approved individually " +
                  "are left alone."
              )
            )
              return;
            act(
              "/api/baseline/clear-attestations",
              (r) => `Cleared ${r.reverted} bulk attestation(s)`
            );
          }}
        >
          <Eraser size={16} className="mr-2" />
          Clear bulk attestations
        </Button>
      </div>
      <p className="text-xs text-muted-foreground max-w-2xl">
        <strong>Finish learning now</strong> is a policy action — it changes
        alerting posture and does not touch any device record, so it never
        claims you verified something you have not seen.
      </p>
    </div>
  );
}
