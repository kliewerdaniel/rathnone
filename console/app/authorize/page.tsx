"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api, FINANCE_CAPS, type Decision } from "../../lib/api";

function AuthorizeInner() {
  const params = useSearchParams();
  const [tid, setTid] = useState<string>(params.get("t") || "");
  const [cap, setCap] = useState<string>(FINANCE_CAPS[0]);
  const [action, setAction] = useState<string>("transfer(USDC, 50000, 0xAB..)");
  const [requestId, setRequestId] = useState<string>("req-" + Math.random().toString(16).slice(2, 8));
  const [human, setHuman] = useState<boolean>(false);
  const [livePayload, setLivePayload] = useState<string>(
    '{"to":"0xAB","value":"1000000000000000000","nonce":1}'
  );
  const [liveResult, setLiveResult] = useState<{ sig: string; addr: string } | null>(null);
  const [results, setResults] = useState<{ decision: Decision; verify: boolean }[]>([]);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    const t = params.get("t");
    if (t) setTid(t);
  }, [params]);

  async function run() {
    setErr("");
    try {
      const r = await api.authorize(tid, {
        producer: "console-strategy",
        request_id: requestId,
        capability: cap,
        action_descriptor: action,
        require_human_approval: human,
      });
      setResults((prev) => [{ decision: r.decision as Decision, verify: r.verify }, ...prev]);
    } catch (e) {
      setErr(String(e));
    }
  }

  async function runLive() {
    setErr("");
    try {
      let payload: object;
      try {
        payload = JSON.parse(livePayload);
      } catch {
        throw new Error("payload is not valid JSON");
      }
      const r = await api.executeLive(tid, {
        producer: "console-strategy",
        request_id: requestId,
        capability: "rathnone.chain_settle",
        action_descriptor: action,
        payload,
      });
      const rec = (r as { live_record: { signature: string; signer_address: string } }).live_record;
      setLiveResult({ sig: rec.signature, addr: rec.signer_address });
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <>
      <div className="panel">
        <h2>Authorize a finance action</h2>
        <div className="row">
          <input placeholder="tenant_id" value={tid} onChange={(e) => setTid(e.target.value)} />
          <select value={cap} onChange={(e) => setCap(e.target.value)}>
            {FINANCE_CAPS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <input placeholder="action_descriptor" value={action} onChange={(e) => setAction(e.target.value)} />
          <input placeholder="request_id" value={requestId} onChange={(e) => setRequestId(e.target.value)} />
          <label className="muted"><input type="checkbox" checked={human} onChange={(e) => setHuman(e.target.checked)} style={{ minWidth: 0, marginRight: 6 }} />require human approval</label>
          <button onClick={run}>Run decide()</button>
        </div>
        <p className="muted" style={{ marginTop: 10 }}>
          Calls the frozen <code>fleet.epistemic.decide()</code> through the gateway. Verdict from scope + grant + epoch policy only — zero model score (Invariant 1).
        </p>
        {err && <p className="err">{err}</p>}
      </div>

      <div className="panel">
        <h2>Decisions</h2>
        {results.length === 0 ? (
          <p className="muted">No decisions yet.</p>
        ) : (
          <table>
            <thead>
              <tr><th>capability</th><th>verdict</th><th>ledger</th><th>reason</th></tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td className="mono">{r.decision.capability.split(".")[1]}</td>
                  <td><span className={`badge ${r.decision.verdict}`}>{r.decision.verdict}</span></td>
                  <td className={r.verify ? "ok" : "err"}>{r.verify ? "verified" : "FAIL"}</td>
                  <td className="muted">{r.decision.reason || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Live settlement (opt-in, fail-closed)</h2>
        <p className="muted">
          Only available for a tenant minted with the <code>live</code> track. Runs the
          frozen <code>decide()</code> again; if AUTO, commits a <strong>real</strong> secp256k1
          (Ethereum) signature over the intent. Anyone can verify it from the address alone.
        </p>
        <div className="row" style={{ marginTop: 10 }}>
          <input
            style={{ minWidth: 360, flex: 1 }}
            placeholder='settlement intent JSON'
            value={livePayload}
            onChange={(e) => setLivePayload(e.target.value)}
          />
          <button onClick={runLive}>Sign live settlement</button>
        </div>
        {liveResult && (
          <div className="row" style={{ marginTop: 12, flexDirection: "column", alignItems: "flex-start" }}>
            <span className="muted">settlement address:</span>
            <div className="pre mono accent">{liveResult.addr}</div>
            <span className="muted">signature (r||s||v):</span>
            <div className="pre mono">{liveResult.sig}</div>
          </div>
        )}
      </div>
    </>
  );
}

export default function AuthorizePage() {
  return (
    <Suspense fallback={<div className="panel"><p className="muted">loading…</p></div>}>
      <AuthorizeInner />
    </Suspense>
  );
}
