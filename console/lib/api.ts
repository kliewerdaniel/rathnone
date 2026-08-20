// Rathnone console client. Talks to the local-first gateway (FastAPI).
// The signing key never leaves the gateway; the console holds only what the
// gateway returns (tenant public key, decisions, signed ledger).

export const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY || "http://127.0.0.1:8765";

async function req(path: string, init?: RequestInit) {
  const res = await fetch(`${GATEWAY}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json();
}

export type Decision = {
  verdict: string;
  capability: string;
  request_ref: string;
  grant_ref: string;
  scope_ref: string;
  epoch: number;
  reason: string;
};

export type LedgerEntry = Record<string, unknown>;

export type MeterSummary = {
  tenant_id: string;
  authorized_actions: number;
  total_actions: number;
  aum_exposure: number;
  aum_fee_rate: number;
  billable: number;
};

export const api = {
  listTenants: () => req("/tenants"),
  createTenant: (aum: number, live = false) =>
    req("/tenants", { method: "POST", body: JSON.stringify({ aum, live }) }),
  authorize: (tid: string, body: object) =>
    req(`/tenants/${tid}/authorize`, { method: "POST", body: JSON.stringify(body) }),
  audit: (tid: string) => req(`/tenants/${tid}/audit`),
  meter: (tid: string) => req(`/tenants/${tid}/meter`),
  executeLive: (tid: string, body: object) =>
    req(`/tenants/${tid}/execute_live`, { method: "POST", body: JSON.stringify(body) }),
};

export const FINANCE_CAPS = [
  "rathnone.trade_execute",
  "rathnone.treasury_rebalance",
  "rathnone.chain_settle",
];
