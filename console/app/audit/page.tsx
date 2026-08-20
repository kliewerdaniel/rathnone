"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api, type MeterSummary } from "../../lib/api";

function AuditInner() {
  const params = useSearchParams();
  const [tid, setTid] = useState<string>(params.get("t") || "");
  const [records, setRecords] = useState<Record<string, unknown>[]>([]);
  const [verifyOk, setVerifyOk] = useState<boolean | null>(null);
  const [meter, setMeter] = useState<MeterSummary | null>(null);
  const [err, setErr] = useState<string>("");

  async function load() {
    setErr("");
    if (!tid) { setErr("enter a tenant_id"); return; }
    try {
      const a = await api.audit(tid);
      setRecords(a.records);
      setVerifyOk(a.verify_ok);
      const m = await api.meter(tid);
      setMeter(m);
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => {
    const t = params.get("t");
    if (t) { setTid(t); load(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  return (
    <>
      <div className="panel">
        <h2>Forensic audit &amp; metering</h2>
        <div className="row">
          <input placeholder="tenant_id" value={tid} onChange={(e) => setTid(e.target.value)} />
          <button onClick={load}>Load</button>
        </div>
        {err && <p className="err">{err}</p>}
      </div>

      {records.length > 0 && (
        <div className="panel">
          <h2>Immutable signed ledger</h2>
          <p className={verifyOk ? "ok" : "err"}>
            chain verify: {verifyOk ? "OK — every signature + link valid (key-free)" : "FAILED"}
          </p>
          <table>
            <thead>
              <tr><th className="mono">seq</th><th>event</th><th>capability</th><th>verdict</th><th className="mono">prev</th></tr>
            </thead>
            <tbody>
              {records.map((r, i) => (
                <tr key={i}>
                  <td className="mono">{String(r.seq)}</td>
                  <td className="muted">{String(r.event)}</td>
                  <td className="mono">{String(r.capability).split(".")[1]}</td>
                  <td><span className={`badge ${String(r.verdict)}`}>{String(r.verdict)}</span></td>
                  <td className="mono">{String(r.prev).slice(0, 10)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {records.some((r) => r.event === "live_sign") && (
        <div className="panel">
          <h2>Live settlement signatures (real, on-chain-verifiable)</h2>
          <p className="muted">
            Each row is a genuine secp256k1 (Ethereum) signature over the authorized intent,
            committed to the immutable ledger. Verify against the settlement address with any
            Ethereum client — no gateway key required.
          </p>
          {records.filter((r) => r.event === "live_sign").map((r, i) => (
            <div className="row" key={i} style={{ marginTop: 10, flexDirection: "column", alignItems: "flex-start" }}>
              <span className="muted">settlement address:</span>
              <div className="pre mono accent">{String(r.settlement_address)}</div>
              <span className="muted">intent hash (keccak256):</span>
              <div className="pre mono">{String(r.intent_hash)}</div>
              <span className="muted">live signature (r||s||v):</span>
              <div className="pre mono">{String(r.live_signature)}</div>
              {(r.action_id !== undefined && r.action_id !== null) && (
                <a className="muted" href={`/trace?t=${encodeURIComponent(tid)}&a=${encodeURIComponent(String(r.action_id))}`}>
                  view authorization trace →
                </a>
              )}
            </div>
          ))}
        </div>
      )}

      {meter && (
        <div className="panel">
          <h2>Per-AUM meter (B9)</h2>
          <div className="metric">
            <div><div className="k">authorized actions</div><div className="v">{meter.authorized_actions}</div></div>
            <div><div className="k">total actions</div><div className="v">{meter.total_actions}</div></div>
            <div><div className="k">AUM exposure</div><div className="v">${meter.aum_exposure.toLocaleString()}</div></div>
            <div><div className="k">fee rate</div><div className="v">{(meter.aum_fee_rate * 10000).toFixed(1)} bps</div></div>
            <div><div className="k">billable</div><div className="v ok">${meter.billable.toLocaleString()}</div></div>
          </div>
          <p className="muted" style={{ marginTop: 12 }}>
            Metering accrues only on AUTO actions; the cloud mirror verifies this with the tenant&apos;s public key only.
          </p>
        </div>
      )}
    </>
  );
}

export default function AuditPage() {
  return (
    <Suspense fallback={<div className="panel"><p className="muted">loading…</p></div>}>
      <AuditInner />
    </Suspense>
  );
}
