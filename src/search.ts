import type { Config } from "./config.js";
import { enc, type SplunkClient } from "./client.js";
import { SplunkMcpError } from "./errors.js";
import { cleanRow, type Row } from "./format.js";
import { isBlockedHost, mentionsBlockedHost } from "./spl.js";

export interface JobStatus {
  sid: string;
  dispatch_state: string;
  is_done: boolean;
  is_failed: boolean;
  done_progress: number;
  result_count: number;
  scan_count: number;
  event_count: number;
  run_duration_s: number;
  messages: string[];
}

interface JobEntry {
  entry?: Array<{ content?: Record<string, unknown> }>;
}

/**
 * Only jobs started by this server process may be read. Any other sid (an alert
 * job, a search from the Splunk UI) could contain data without the host filter.
 */
const ownJobs = new Map<string, string>();

export function registerJob(sid: string, environment: string): void {
  ownJobs.set(sid, environment);
}

export function assertOwnJob(sid: string, environment: string): void {
  const owner = ownJobs.get(sid);
  if (owner === undefined) {
    throw new SplunkMcpError("UNKNOWN_SID", "This job id was not created by this server in this session.", {
      hint: "Only jobs started with splunk_search or splunk_start_search in this session can be read. Run the search again.",
    });
  }
  if (owner !== environment) {
    throw new SplunkMcpError("UNKNOWN_SID", `This job belongs to environment ${owner}, not ${environment}.`, {
      hint: `Use environment ${owner} for this sid.`,
    });
  }
}

/** Last line of defence: drops every row that comes from or mentions a blocked host. */
export function dropBlockedRows(rows: Row[], blockedHosts: string[]): { rows: Row[]; blocked: number } {
  const kept: Row[] = [];
  let blocked = 0;
  for (const row of rows) {
    const hostValue = row.host;
    const hosts = Array.isArray(hostValue) ? hostValue.map(String) : hostValue === undefined ? [] : [String(hostValue)];
    const bad =
      hosts.some((h) => isBlockedHost(h, blockedHosts)) ||
      Object.values(row).some((v) =>
        Array.isArray(v)
          ? v.some((x) => typeof x === "string" && mentionsBlockedHost(x, blockedHosts))
          : typeof v === "string" && mentionsBlockedHost(v, blockedHosts),
      );
    if (bad) blocked++;
    else kept.push(row);
  }
  return { rows: kept, blocked };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function num(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export async function createJob(
  client: SplunkClient,
  query: string,
  opts: { earliest: string; latest: string; app: string; autoCancelS?: number },
): Promise<string> {
  const user = await client.username();
  const res = await client.post<{ sid?: string }>(`/servicesNS/${enc(user)}/${enc(opts.app)}/search/v2/jobs`, {
    search: query,
    earliest_time: opts.earliest,
    latest_time: opts.latest,
    exec_mode: "normal",
    auto_cancel: opts.autoCancelS,
  });
  if (!res.sid) throw new SplunkMcpError("SPLUNK_ERROR", "Splunk did not return a job id (sid).");
  registerJob(res.sid, client.env.name);
  return res.sid;
}

export async function jobStatus(client: SplunkClient, sid: string): Promise<JobStatus> {
  assertOwnJob(sid, client.env.name);
  const res = await client.get<JobEntry>(`/services/search/v2/jobs/${enc(sid)}`);
  const c = res.entry?.[0]?.content ?? {};
  const messages = Array.isArray(c.messages)
    ? (c.messages as Array<{ type?: string; text?: string }>).map((m) => `${m.type ?? "INFO"}: ${m.text ?? ""}`)
    : [];
  return {
    sid,
    dispatch_state: String(c.dispatchState ?? "UNKNOWN"),
    is_done: c.isDone === true || c.isDone === "1",
    is_failed: c.isFailed === true || c.isFailed === "1",
    done_progress: Math.round(num(c.doneProgress) * 100) / 100,
    result_count: num(c.resultCount),
    scan_count: num(c.scanCount),
    event_count: num(c.eventCount),
    run_duration_s: Math.round(num(c.runDuration) * 100) / 100,
    messages,
  };
}

/** Polls until the job is done; throws TIMEOUT (job keeps running) or JOB_FAILED. */
export async function waitForJob(client: SplunkClient, sid: string, timeoutS: number): Promise<JobStatus> {
  const deadline = Date.now() + timeoutS * 1000;
  let delay = 200;
  for (;;) {
    const status = await jobStatus(client, sid);
    if (status.is_failed) {
      throw new SplunkMcpError("JOB_FAILED", `Search job failed: ${status.messages.join(" | ") || status.dispatch_state}`, {
        splunkMessages: status.messages,
        meta: { sid, environment: client.env.name },
        hint: "Read the Splunk messages, fix the query and run it again.",
      });
    }
    if (status.is_done) return status;
    if (Date.now() + delay > deadline) {
      throw new SplunkMcpError("TIMEOUT", `The search did not finish within ${timeoutS} s. It keeps running.`, {
        meta: { sid, environment: client.env.name, done_progress: status.done_progress },
        hint: "Call splunk_get_job_status with this sid later, then splunk_get_job_results. Or cancel it with splunk_cancel_job and narrow the time range.",
      });
    }
    await sleep(delay);
    delay = Math.min(Math.round(delay * 1.5), 2000);
  }
}

export async function jobResults(
  client: SplunkClient,
  sid: string,
  opts: { offset: number; count: number; fields?: string[]; blockedHosts: string[] },
): Promise<{ rows: Row[]; fetched: number; blocked: number; messages: string[] }> {
  assertOwnJob(sid, client.env.name);
  const res = await client.get<{ results?: Row[]; messages?: Array<{ type?: string; text?: string }> }>(
    `/services/search/v2/jobs/${enc(sid)}/results`,
    { offset: opts.offset, count: opts.count },
  );
  const raw = res.results ?? [];
  // Filter on the full rows, before any field selection hides the host.
  const { rows, blocked } = dropBlockedRows(raw, opts.blockedHosts);
  return {
    rows: rows.map((r) => cleanRow(r, opts.fields)),
    fetched: raw.length,
    blocked,
    messages: (res.messages ?? []).map((m) => `${m.type ?? "INFO"}: ${m.text ?? ""}`),
  };
}

export function clampRows(requested: number | undefined, fallback: number, config: Config): number {
  const n = requested ?? fallback;
  return Math.max(1, Math.min(n, config.maxRows));
}

export function webUrl(
  client: SplunkClient,
  config: Config,
  app: string,
  query: string,
  earliest: string,
  latest: string,
): string {
  const params = new URLSearchParams({ q: query, earliest, latest });
  return `${config.connection.webUrl}/${config.locale}/app/${enc(app)}/search?${params.toString()}`;
}

/** Runs a query to completion and returns cleaned rows. Used by helper tools. */
export async function runSearch(
  client: SplunkClient,
  config: Config,
  query: string,
  opts: { earliest: string; latest: string; app: string; maxRows: number; fields?: string[] },
): Promise<{ sid: string; status: JobStatus; rows: Row[]; fetched: number; blocked: number; messages: string[] }> {
  const sid = await createJob(client, query, { ...opts, autoCancelS: 300 });
  const status = await waitForJob(client, sid, config.searchTimeoutS);
  const res = await jobResults(client, sid, {
    offset: 0,
    count: opts.maxRows,
    fields: opts.fields,
    blockedHosts: config.blockedHosts,
  });
  return { sid, status, ...res };
}
