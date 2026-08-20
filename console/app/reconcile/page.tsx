"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "../../lib/api";

type Summary = {
  tenant_id: string;
  total_actions: number;
  matched: number;
  divergence_count: number;
  divergences: { action_id: string; capability: string; code: string; detail: string; venue_state: string }[];
  per_code: Record<string, number>;
  all_matched: boolean;
};

function ReconcileInner() {
  const params = useSearchParams();
  const [tid, setTid] = useState<string>(params.get("t") || "");
  const [s, setS] = useState<Summary | null>(null);
  const [err, setErr] = useState<string>("");

  async function load() {
    if (!tid) return;
    setErr("");
    try {
      setS(await api.reconciliation(tid));
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    const t = params.get("t");
    if (t) setTid(t);
  }, [params]);

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [tid]);

  return (
    <>
      <div className="panel">
        <h2>Cross-action reconciliation</h2>
        <div className="row">
          <input placeholder="tenant_id" value={tid} onChange={(e) => setTid(e.target.value)} />
          <button onClick={load}>Refresh</button>
        </div>
        <p className="muted" style={{ marginTop: 8 }}>
          Aggregated from the durable per-action reconciliation codes the control
          plane committed to the tenant ledger. It does not re-query the venue.
        </p>
        {err && <p className="err">{err}</p>}
      </div>

      {s && (
        <div className="panel">
          <div className="row" style={{ marginTop: 8 }}>
            <span className="muted">actions:</span><strong>{s.total_actions}</strong>
            <span className="muted">matched:</span><span className="ok">{s.matched}</span>
            <span className="muted">divergences:</span>
            <span className={s.divergence_count ? "err" : "ok"}>{s.divergence_count}</span>
            <span className={`badge ${s.all_matched ? "AUTO" : "BLOCKED"}`}>
              {s.all_matched ? "ALL MATCHED" : "DIVERGENCE"}
            </span>
          </div>

          {s.divergence_count === 0 ? (
            <p className="ok" style={{ marginTop: 12 }}>
              {s.total_actions > 0
                ? "Every authorized action settled as authorized."
                : "No pipeline actions yet."}
            </p>
          ) : (
            <table style={{ marginTop: 12 }}>
              <thead>
                <tr><th>action</th><th>capability</th><th>code</th><th>venue</th><th>detail</th></tr>
              </thead>
              <tbody>
                {s.divergences.map((d, i) => (
                  <tr key={i}>
                    <td className="mono">{d.action_id}</td>
                    <td className="mono">{d.capability?.split(".")[1] || "—"}</td>
                    <td className="err">{d.code}</td>
                    <td className="muted">{d.venue_state}</td>
                    <td className="muted">{d.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {Object.keys(s.per_code).length > 0 && (
            <p className="muted" style={{ marginTop: 12 }}>
              breakdown: {Object.entries(s.per_code).map(([k, v]) => `${k}=${v}`).join("  ")}
            </p>
          )}
        </div>
      )}
    </>
  );
}

export default function ReconcilePage() {
  return (
    <Suspense fallback={<div className="panel"><p className="muted">loading…</p></div>}>
      <ReconcileInner />
    </Suspense>
  );
}
