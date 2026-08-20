"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "../../lib/api";

// Maps an EvidenceEvent.event_type to the control-plane layer label.
const LAYER_LABEL: Record<string, string> = {
  EPISTEMIC: "1 · Epistemic (frozen spine)",
  AUTHORIZED: "2 · Policy / Authorization",
  RISK: "3 · Risk (narrowing)",
  APPROVAL: "4 · Human approval",
  REPLAY: "5 · Replay / isolation",
  BREAKER: "6 · Circuit breaker",
  SETTLEMENT: "7 · Settlement gate",
  SIGNATURE: "8 · Signer (live)",
  SUBMISSION: "9 · Venue submit",
  RECONCILIATION: "10 · Reconciliation",
  EVIDENCE: "11 · Evidence ledger",
  REJECTION: "✗ Rejection",
};

function TraceInner() {
  const params = useSearchParams();
  const [tid, setTid] = useState<string>(params.get("t") || "");
  const [actionId, setActionId] = useState<string>(params.get("a") || "");
  const [events, setEvents] = useState<Record<string, any>[]>([]);
  const [currentState, setCurrentState] = useState<string | null>(null);
  const [transitionViolations, setTransitionViolations] = useState<string[]>([]);
  const [chainIntegrityOk, setChainIntegrityOk] = useState<boolean | null>(null);
  const [err, setErr] = useState<string>("");

  async function load() {
    setErr("");
    if (!tid || !actionId) {
      setErr("enter both a tenant_id and an action_id");
      return;
    }
    try {
      const t = await api.evidence(tid, actionId);
      setEvents(t.events || []);
      setCurrentState(t.current_state || null);
      setTransitionViolations(t.transition_violations || []);
      setChainIntegrityOk(t.chain_integrity_ok ?? null);
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    const t = params.get("t");
    const a = params.get("a");
    if (t) setTid(t);
    if (a) setActionId(a);
    if (t && a) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  return (
    <>
      <div className="panel">
        <h2>Authorization trace (v2 control plane)</h2>
        <p className="muted">
          The causal evidence chain for a single action — every layer of the
          pipeline as it actually executed: epistemic verdict → risk →
          approval → replay → settlement → signer → venue → reconciliation →
          evidence. Verified key-free against the tenant ledger.
        </p>
        <div className="row">
          <input placeholder="tenant_id" value={tid} onChange={(e) => setTid(e.target.value)} />
          <input placeholder="action_id" value={actionId} onChange={(e) => setActionId(e.target.value)} />
          <button onClick={load}>Trace</button>
        </div>
        {err && <p className="err">{err}</p>}
      </div>

      {events.length > 0 && (
        <div className="panel">
          <h2>Action {String(actionId).slice(0, 12)}…</h2>
          <div className="row" style={{ marginBottom: 14 }}>
            <span className="muted">final state:</span>
            <span className={`badge ${String(currentState)}`}>{currentState}</span>
            <span className="muted">chain integrity:</span>
            <span className={chainIntegrityOk ? "ok" : "err"}>
              {chainIntegrityOk ? "OK" : "FAILED"}
            </span>
          </div>
          {transitionViolations.length > 0 ? (
            <p className="err">{transitionViolations.join("; ")}</p>
          ) : (
            <p className="ok">all state transitions legal</p>
          )}

          <div className="trace">
            {events.map((ev, i) => (
              <div className="trace-row" key={i}>
                <div className="trace-rail">
                  <span className={`dot ${String(ev.state)}`} />
                  {i < events.length - 1 && <span className="rail-line" />}
                </div>
                <div className="trace-body">
                  <div className="trace-head">
                    <span className="trace-layer">{LAYER_LABEL[String(ev.event_type)] || ev.event_type}</span>
                    <span className={`badge ${String(ev.state)}`}>{String(ev.state)}</span>
                  </div>
                  {ev.prev_event_hash ? (
                    <div className="muted mono small">
                      prev: {String(ev.prev_event_hash).slice(0, 16)}…
                    </div>
                  ) : (
                    <div className="muted mono small">prev: — (root)</div>
                  )}
                  {Object.keys(ev.payload || {}).length > 0 && (
                    <div className="pre mono" style={{ marginTop: 6 }}>
                      {JSON.stringify(ev.payload, null, 2)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

export default function TracePage() {
  return (
    <Suspense fallback={<div className="panel"><p className="muted">loading…</p></div>}>
      <TraceInner />
    </Suspense>
  );
}
