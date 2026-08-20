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
  const [downgradePayload, setDowngradePayload] = useState<string>("{}");
  const [downgradeResult, setDowngradeResult] = useState<{ verdict: string; downgraded?: boolean; downgrade_violations?: string[] } | null>(null);
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

  async function runDowngrade() {
    setErr("");
    setDowngradeResult(null);
    try {
      let payload: any;
      try {
        payload = JSON.parse(downgradePayload);
      } catch {
        throw new Error("downgrade payload is not valid JSON");
      }
      // ADR 18: the SAME authorize_action endpoint, with a signed downgrade
      // record. The gateway verifies the operator signature(s) and — on success
      // — re-enters the action at the HUMAN band. Spine-BLOCKED is refused.
      const r = await api.authorizeActionDowngrade(tid, { action: payload.action, downgrade: payload.downgrade });
      setDowngradeResult({ verdict: r.verdict, downgraded: r.downgraded, downgrade_violations: r.downgrade_violations });
    } catch (e) {
      setErr(String(e));
    }
  }

  async function runLive() {
    setErr("");
    try {
      let payload: any;
      try {
        payload = JSON.parse(livePayload);
      } catch {
        throw new Error("payload is not valid JSON");
      }
      // v2 control plane: the SAME action object is authorized AND signed. There
      // is no separate "payload" that gets bound after the fact — the signing
      // layer signs over the canonical FinancialAction hash (see ADR 17).
      const action = {
        action_id: requestId,
        tenant_id: tid,
        actor: "console-strategy",
        capability: "rathnone.chain_settle",
        side: "settle",
        destination: payload.to,
        quantity: Number(payload.value || 0),
        currency: "wei",
        settlement_asset: "wei",
        nonce: Number(payload.nonce || 0),
        ...payload,
      };
      const r = await api.authorizeAction(tid, { action, denylist: [] });
      const rec = (r as { live_record: { signature: string; signer_address: string } }).live_record;
      if (!rec) {
        throw new Error(`not signed: ${r.verdict} ${r.blocked_reason || ""}`);
      }
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
          <>
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
            {results.some((r) => typeof r.decision.hygiene_ok === "boolean") && (
              <div style={{ marginTop: 12 }}>
                <h3>Epistemic hygiene</h3>
                {results.filter((r) => typeof r.decision.hygiene_ok === "boolean").map((r, i) => (
                  <div key={i} className="row" style={{ alignItems: "flex-start" }}>
                    <span className={`badge ${r.decision.hygiene_ok ? "AUTO" : "BLOCKED"}`}>
                      {r.decision.hygiene_ok ? "corroborated" : "UNCORROBORATED"}
                    </span>
                    {r.decision.hygiene_ok ? (
                      <span className="muted">all economic claims independently corroborated</span>
                    ) : (
                      <span className="err">
                        {(r.decision.hygiene_violations || []).map((v) => v.code).join(", ")}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
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

      <div className="panel">
        <h2>Operator downgrade (ADR 18, fail-closed)</h2>
        <p className="muted">
          Release a hygiene-BLOCKED action via a <strong>signed</strong> operator
          downgrade. The gateway verifies the signature against the tenant&apos;s
          operator allowlist; a 2-of-2 operator signature is required to release a
          <code> destination_off_allowlist</code> / <code>destination_untrusted</code>{" "}
          override. Spine-BLOCKED actions can never be downgraded.
        </p>
        <div className="row" style={{ marginTop: 10 }}>
          <input
            style={{ minWidth: 360, flex: 1 }}
            placeholder='{ "action": {...}, "downgrade": {...} }'
            value={downgradePayload}
            onChange={(e) => setDowngradePayload(e.target.value)}
          />
          <button onClick={runDowngrade}>Submit downgrade</button>
        </div>
        {downgradeResult && (
          <div className="row" style={{ marginTop: 12, flexDirection: "column", alignItems: "flex-start" }}>
            <span className="muted">verdict:</span>
            <div className={`badge ${downgradeResult.verdict}`}>{downgradeResult.verdict}</div>
            {downgradeResult.downgraded && (
              <span className="ok">released violations: {downgradeResult.downgrade_violations?.join(", ")}</span>
            )}
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
