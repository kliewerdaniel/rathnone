// Rathnone console client. Talks to the local-first gateway (FastAPI).
// The signing key never leaves the gateway; the console holds only what the
// gateway returns (tenant public key, decisions, signed ledger).

export const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY || "http://127.0.0.1:8765";

// ADR 17: when the control plane is locked down (RATHNONE_ENFORCE_AUTH=1), the
// gateway requires a static API key on every gated route. The key is supplied at
// deploy time (NEXT_PUBLIC_RATHNONE_API_KEY) and sent as a Bearer token. Dev /
// local-first deployments leave enforcement off and the header is omitted, so the
// console works unchanged against an open gateway.
const ENFORCE_AUTH = process.env.NEXT_PUBLIC_RATHNONE_ENFORCE_AUTH === "1";
const API_KEY = process.env.NEXT_PUBLIC_RATHNONE_API_KEY || "";

function authHeaders(): Record<string, string> {
  if (ENFORCE_AUTH && API_KEY) {
    return { Authorization: `Bearer ${API_KEY}` };
  }
  return {};
}

async function req(path: string, init?: RequestInit) {
  const res = await fetch(`${GATEWAY}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init?.headers || {}),
    },
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
  // v3 epistemic-hygiene gate (present on /authorize_action; optional on v1 path)
  hygiene_ok?: boolean;
  hygiene_violations?: { code: string; message: string; detail?: unknown }[];
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
  reconciliation: (tid: string) => req(`/tenants/${tid}/reconciliation`),
  evidence: (tid: string, actionId: string) =>
    req(`/tenants/${tid}/evidence/${actionId}`),
  // ADR 20: non-secret tenant metadata (operator visibility). The console uses
  // `operator_gated` to know whether a tenant requires operator-signed transport
  // — which the console cannot provide (custody design), so the live-settle
  // control is disabled for such tenants.
  tenantInfo: (tid: string) => req(`/tenants/${tid}`),
  // v2 control plane: the SINGLE path to authorization + (opt-in) live signing.
  authorizeAction: (tid: string, body: object) =>
    req(`/tenants/${tid}/authorize_action`, { method: "POST", body: JSON.stringify(body) }),
  // ADR 18: operator downgrade of a hygiene-BLOCKED action. `downgrade` is the
  // signed DowngradeRecord produced by the operator key; it re-enters the action
  // at the HUMAN band. Mirrors authorizeAction (same endpoint, extra field).
  authorizeActionDowngrade: (tid: string, body: object) =>
    req(`/tenants/${tid}/authorize_action`, { method: "POST", body: JSON.stringify(body) }),
  safety: () => req(`/safety`),
  safetyHalt: () => req(`/safety/halt`, { method: "POST" }),
  safetyResume: () => req(`/safety/resume`, { method: "POST" }),
};

export const FINANCE_CAPS = [
  "rathnone.trade_execute",
  "rathnone.treasury_rebalance",
  "rathnone.chain_settle",
];
