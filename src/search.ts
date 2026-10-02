import type { Config } from "./config.js";
import { enc, type SplunkClient } from "./client.js";
import { SplunkMcpError } from "./errors.js";
import { cleanRow, type Row } from "./format.js";

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
  return res.sid;
}

export async function jobStatus(client: SplunkClient, sid: string): Promise<JobStatus> {
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
  opts: { offset: number; count: number; fields?: string[] },
): Promise<{ rows: Row[]; messages: string[] }> {
  const res = await client.get<{ results?: Row[]; messages?: Array<{ type?: string; text?: string }> }>(
    `/services/search/v2/jobs/${enc(sid)}/results`,
    { offset: opts.offset, count: opts.count },
  );
  return {
    rows: (res.results ?? []).map((r) => cleanRow(r, opts.fields)),
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
  return `${client.env.webUrl}/${config.locale}/app/${enc(app)}/search?${params.toString()}`;
}

/** Runs a query to completion and returns cleaned rows. Used by helper tools. */
export async function runSearch(
  client: SplunkClient,
  config: Config,
  query: string,
  opts: { earliest: string; latest: string; app: string; maxRows: number; fields?: string[] },
): Promise<{ sid: string; status: JobStatus; rows: Row[]; messages: string[] }> {
  const sid = await createJob(client, query, { ...opts, autoCancelS: 300 });
  const status = await waitForJob(client, sid, config.searchTimeoutS);
  const { rows, messages } = await jobResults(client, sid, { offset: 0, count: opts.maxRows, fields: opts.fields });
  return { sid, status, rows, messages };
}
