"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { api } from "../../lib/api";

export default function SafetyPage() {
  const [state, setState] = useState<{ breaker_open: boolean; live_signing_enabled: boolean } | null>(null);
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState<boolean>(false);
  const [flash, setFlash] = useState<string>("");
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  async function refresh() {
    try {
      const s = await api.safety();
      setState(s);
      setErr("");
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    refresh();
    timer.current = setInterval(refresh, 2000);
    return () => { if (timer.current) clearInterval(timer.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function halt() {
    setBusy(true); setErr("");
    try {
      await api.safetyHalt();
      setFlash("circuit breaker TRIPPED — live signing halted (independent of frozen spine)");
      await refresh();
    } catch (e) {
      setErr(String(e));
    } finally { setBusy(false); }
  }
  async function resume() {
    setBusy(true); setErr("");
    try {
      await api.safetyResume();
      setFlash("circuit breaker CLEARED — live signing resumed");
      await refresh();
    } catch (e) {
      setErr(String(e));
    } finally { setBusy(false); }
  }

  const open = state?.breaker_open ?? false;

  return (
    <div className="panel">
      <h2>Operator safety control (V4)</h2>
      <p className="muted">
        The circuit breaker is an <strong>independent halt</strong> for the autonomous loop.
        It stops live signing and execution <strong>without requiring the frozen
        <code> fleet.epistemic.decide()</code> to agree</strong> — the antidote to the
        &ldquo;immutable cage&rdquo; failure mode. Trip it whenever you would not trust the
        agent to keep acting; resume only on explicit operator action.
      </p>

      <div className="row" style={{ marginTop: 8 }}>
        <span className="muted">breaker:</span>
        {state === null ? (
          <span className="muted">…</span>
        ) : open ? (
          <span className="badge BLOCKED">OPEN — halted</span>
        ) : (
          <span className="badge AUTO">CLOSED — running</span>
        )}
        <span className="muted">live signing:</span>
        <span className={state?.live_signing_enabled ? "ok" : "err"}>
          {state ? (state.live_signing_enabled ? "enabled" : "disabled") : "—"}
        </span>
      </div>

      <div className="row" style={{ marginTop: 16 }}>
        <button onClick={halt} disabled={busy || open}
          style={{ borderColor: "var(--blocked)", color: "var(--blocked)" }}>
          Trip breaker (halt)
        </button>
        <button onClick={resume} disabled={busy || !open}
          style={{ borderColor: "var(--auto)", color: "var(--auto)" }}>
          Clear breaker (resume)
        </button>
      </div>

      {flash && <p className="ok" style={{ marginTop: 12 }}>{flash}</p>}
      {err && <p className="err">{err}</p>}

      <p className="muted" style={{ marginTop: 16, fontSize: 12 }}>
        State auto-refreshes every 2s. When OPEN, every live-signing and execution
        endpoint returns 503 regardless of the model&apos;s verdict.
      </p>
    </div>
  );
}
