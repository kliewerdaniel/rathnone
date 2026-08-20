"use client";

import { useEffect, useState } from "react";
import { api } from "../lib/api";

export default function TenantsPage() {
  const [ids, setIds] = useState<string[]>([]);
  const [aum, setAum] = useState<string>("1000000");
  const [live, setLive] = useState<boolean>(false);
  const [created, setCreated] = useState<{ tenant_id: string; public_key_pem: string; settlement_address: string | null } | null>(null);
  const [err, setErr] = useState<string>("");

  async function refresh() {
    try {
      const r = await api.listTenants();
      setIds(r.tenant_ids as string[]);
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { refresh(); }, []);

  async function mint() {
    setErr("");
    try {
      const r = await api.createTenant(Number(aum), live);
      setCreated(r);
      await refresh();
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <>
      <div className="panel">
        <h2>Provision tenant</h2>
        <div className="row">
          <input placeholder="reported AUM (USD)" value={aum} onChange={(e) => setAum(e.target.value)} />
          <label className="check">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> live track (real signing)
          </label>
          <button onClick={mint}>Mint tenant (new Ed25519 key)</button>
        </div>
        {err && <p className="err">{err}</p>}
        {created && (
          <div className="row" style={{ marginTop: 12, flexDirection: "column", alignItems: "flex-start" }}>
            <span className="ok">minted: {created.tenant_id}</span>
            <span className="muted">public key (audit-only, key-free):</span>
            <div className="pre">{created.public_key_pem}</div>
            {created.settlement_address ? (
              <>
                <span className="muted">settlement address (live, secp256k1):</span>
                <div className="pre mono accent">{created.settlement_address}</div>
              </>
            ) : (
              <span className="muted">settlement address: none (mint with live track enabled)</span>
            )}
          </div>
        )}
      </div>

      <div className="panel">
        <h2>Active tenants ({ids.length})</h2>
        {ids.length === 0 ? (
          <p className="muted">No tenants yet.</p>
        ) : (
          <table>
            <thead>
              <tr><th className="mono">tenant_id</th><th>links</th></tr>
            </thead>
            <tbody>
              {ids.map((id) => (
                <tr key={id}>
                  <td className="mono">{id}</td>
                  <td>
                    <a href={`/authorize?t=${id}`}>authorize</a> ·{" "}
                    <a href={`/audit?t=${id}`}>audit</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
