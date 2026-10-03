import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { ClientPool, enc, type SplunkClient } from "./client.js";
import { type Config, log } from "./config.js";
import { SplunkMcpError } from "./errors.js";
import { contains, fail, isoTime, ok, type Row } from "./format.js";
import { assertOwnJob, clampRows, createJob, dropBlockedRows, jobResults, jobStatus, runSearch, webUrl } from "./search.js";
import { applyScope, blockedClause, exclusionClauses, hostClause, quote, validateQuery } from "./spl.js";

interface Entry {
  name: string;
  content?: Record<string, unknown>;
  acl?: { app?: string; owner?: string; sharing?: string };
}
interface Feed {
  entry?: Entry[];
  paging?: { total?: number; offset?: number; perPage?: number };
}

type Shape = Record<string, z.ZodType>;
type Ctx = { client: SplunkClient; config: Config };

const INDEX_NAME = /^[A-Za-z0-9_*.\-]+$/;

function assertIndexName(index: string): void {
  if (!INDEX_NAME.test(index)) {
    throw new SplunkMcpError("INVALID_ARGUMENT", `Invalid index name: "${index}".`);
  }
}

function truthy(v: unknown): boolean {
  return v === true || v === 1 || v === "1" || v === "true";
}

function sanitizeFilter(filter?: string): string | undefined {
  const f = filter?.replace(/["\\]/g, "").trim();
  return f ? `name="*${f}*"` : undefined;
}

export function registerTools(server: McpServer, config: Config, pool: ClientPool): void {
  const envNames = [...config.environments.keys()] as [string, ...string[]];
  const environment = z
    .enum(envNames)
    .describe("Environment to query. Each environment is a fixed set of hosts. Ask the user if it was not stated; never guess.");

  /** Registers a read-only tool that takes `environment` as its first parameter. */
  function tool<S extends Shape>(
    name: string,
    description: string,
    shape: S,
    handler: (args: z.infer<z.ZodObject<S>>, ctx: Ctx) => Promise<CallToolResult>,
  ): void {
    server.registerTool(
      name,
      {
        description,
        inputSchema: { environment, ...shape },
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (async (args: any) => {
        const started = Date.now();
        try {
          const client = pool.get(String(args.environment));
          const result = await handler(args, { client, config });
          log(`${name} ${client.env.name} ok ${Date.now() - started} ms`);
          return result;
        } catch (err) {
          log(`${name} ${String(args?.environment)} failed ${Date.now() - started} ms: ${err instanceof Error ? err.message : String(err)}`);
          return fail(err);
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any,
    );
  }

  const maxRows = (fallback: number) =>
    z.number().int().min(1).optional().describe(`Maximum rows to return. Default ${fallback}, capped at ${config.maxRows}.`);
  const offset = z.number().int().min(0).optional().describe("Number of rows to skip. Default 0.");
  const appParam = z.string().optional().describe("Splunk app context. Default: the app configured for the environment.");
  const anyAppParam = z.string().optional().describe("Limit to one Splunk app. Default: all apps.");
  const earliestParam = (dflt: string) =>
    z.string().optional().describe(`Start of the time range as Splunk time modifier, e.g. -15m, -7d@d, 2026-10-01T00:00:00. Default ${dflt}.`);
  const latestParam = z.string().optional().describe("End of the time range as Splunk time modifier. Default now.");

  // ---------------------------------------------------------------- 3.0
  server.registerTool(
    "splunk_list_environments",
    {
      description:
        "List the configured environments with their hosts, app, default sourcetype and active exclusion filters. Use this when the user has not said which environment to use, then ask them to choose.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () =>
      ok(
        {
          data: [...config.environments.values()].map((e) => ({
            name: e.name,
            description: e.description,
            hosts: e.hosts,
            app: e.app,
            default_sourcetype: e.defaultSourcetype ?? null,
            default_index: e.defaultIndex ?? null,
            excluded: exclusionClauses(e),
          })),
          meta: {
            count: config.environments.size,
            session: pool.connection.sessionState,
            pseudonymised: config.redactor !== undefined,
          },
          hint: "Every search is limited to the hosts of the chosen environment. Other hosts cannot be searched.",
        },
        config.maxOutputChars,
      ),
  );

  // ---------------------------------------------------------------- 3.1 search
  const scopeShape = {
    sourcetype: z.string().optional().describe("Overrides the default sourcetype for this call."),
    include_excluded: z
      .boolean()
      .optional()
      .describe("true = disable the exclusion filters (e.g. Spring /actuator requests) for this call. Default false."),
  };

  function prepare(
    args: { query: string; earliest?: string; latest?: string; app?: string; sourcetype?: string; include_excluded?: boolean },
    { client }: Ctx,
  ) {
    validateQuery(args.query, client.env, config.redactor);
    if (args.sourcetype) validateQuery(`sourcetype=${quote(args.sourcetype)}`, client.env, config.redactor);
    const scoped = applyScope(args.query, client.env, {
      sourcetype: args.sourcetype,
      includeExcluded: args.include_excluded,
    });
    const earliest = args.earliest ?? config.defaultEarliest;
    const latest = args.latest ?? "now";
    const app = args.app ?? client.env.app;
    return { scoped, earliest, latest, app };
  }

  /** Notes shared by all tools that return search rows. */
  function blockedNote(blocked: number): string | undefined {
    return blocked > 0
      ? `${blocked} row(s) were removed because they refer to a blocked host. Do not try to retrieve them.`
      : undefined;
  }

  tool(
    "splunk_search",
    "Run an SPL event search and wait for the results. Use this for most questions about log data. The host filter of the environment, the default sourcetype and the exclusion filters are added automatically and cannot be removed; meta.effective_query shows what actually ran. Write only search terms followed by pipes (stats, eval, where, rex, timechart, ...). Not allowed: a leading pipe, subsearches in [ ], macros, and commands that read other data (append, join, tstats, inputlookup, ...). Always set a time range and keep max_rows small; prefer aggregating over fetching raw events. For searches expected to run longer than about two minutes use splunk_start_search.",
    {
      query: z
        .string()
        .describe("SPL event search without host filter, e.g. `level=ERROR | stats count by logger`. Must not start with a pipe."),
      earliest: earliestParam(config.defaultEarliest),
      latest: latestParam,
      max_rows: maxRows(100),
      app: appParam,
      fields: z.array(z.string()).optional().describe("Return only these fields."),
      ...scopeShape,
    },
    async (args, ctx) => {
      const { client } = ctx;
      const { scoped, earliest, latest, app } = prepare(args, ctx);
      const limit = clampRows(args.max_rows, 100, config);
      const { sid, status, rows, fetched, blocked, messages } = await runSearch(client, config, scoped.query, {
        earliest,
        latest,
        app,
        maxRows: limit,
        fields: args.fields,
      });
      const truncated = status.result_count > fetched;
      const hints: string[] = [];
      if (truncated) {
        hints.push(
          `Showing ${fetched} of ${status.result_count} results. Aggregate in SPL or call splunk_get_job_results with sid and offset=${fetched}.`,
        );
      }
      const note = blockedNote(blocked);
      if (note) hints.push(note);
      if (rows.length === 0 && blocked === 0) {
        hints.push(
          "No results. Check meta.effective_query: the host filter, the default sourcetype or the exclusion filter may be the reason. Widen the time range, or use sourcetype / include_excluded if the user wants that.",
        );
      }
      if (earliest === "0" || earliest === "1") hints.push("This was an all-time search, which is expensive.");
      return ok(
        {
          data: rows,
          meta: {
            environment: client.env.name,
            sid,
            count: rows.length,
            total: status.result_count,
            offset: 0,
            scan_count: status.scan_count,
            run_duration_s: status.run_duration_s,
            earliest,
            latest,
            truncated,
            effective_query: scoped.query,
            hosts: client.env.hosts,
            excluded: scoped.excluded,
            ...(blocked > 0 ? { blocked_rows: blocked } : {}),
            web_url: webUrl(client, config, app, scoped.query, earliest, latest),
            ...(messages.length > 0 ? { splunk_messages: messages } : {}),
          },
          hint: hints.join(" ") || undefined,
        },
        config.maxOutputChars,
        "Output was cut to fit the size limit. Aggregate in SPL, request fewer fields, or page with splunk_get_job_results using meta.sid and meta.next_offset.",
      );
    },
  );

  tool(
    "splunk_start_search",
    "Start a long-running SPL event search in the background and return its job id (sid) immediately. Same query rules as splunk_search. Follow up with splunk_get_job_status and then splunk_get_job_results, using the same environment.",
    {
      query: z.string().describe("SPL event search without host filter. Must not start with a pipe."),
      earliest: earliestParam(config.defaultEarliest),
      latest: latestParam,
      app: appParam,
      ...scopeShape,
    },
    async (args, ctx) => {
      const { client } = ctx;
      const { scoped, earliest, latest, app } = prepare(args, ctx);
      const sid = await createJob(client, scoped.query, { earliest, latest, app });
      return ok(
        {
          data: { sid },
          meta: {
            environment: client.env.name,
            earliest,
            latest,
            effective_query: scoped.query,
            hosts: client.env.hosts,
            excluded: scoped.excluded,
            web_url: webUrl(client, config, app, scoped.query, earliest, latest),
          },
          hint: "Poll splunk_get_job_status with this sid until is_done is true, then call splunk_get_job_results.",
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_job_status",
    "Check whether a search job is finished and how far it has progressed. Only works for jobs started by splunk_search or splunk_start_search in this session, in the same environment.",
    { sid: z.string().describe("Search job id returned by splunk_start_search or splunk_search.") },
    async ({ sid }, { client }) => {
      const status = await jobStatus(client, sid);
      return ok(
        {
          data: status,
          meta: { environment: client.env.name },
          hint: status.is_failed
            ? "The job failed. Read messages and fix the query."
            : status.is_done
              ? "Done. Call splunk_get_job_results."
              : "Still running. Check again in a few seconds.",
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_job_results",
    "Fetch a page of results from a finished search job that was started by splunk_search or splunk_start_search in this session. Use offset to page through large result sets.",
    {
      sid: z.string().describe("Search job id."),
      offset,
      max_rows: maxRows(100),
      fields: z.array(z.string()).optional().describe("Return only these fields."),
    },
    async (args, { client }) => {
      const status = await jobStatus(client, args.sid);
      if (status.is_failed) {
        throw new SplunkMcpError("JOB_FAILED", `Search job failed: ${status.messages.join(" | ")}`, {
          splunkMessages: status.messages,
        });
      }
      if (!status.is_done) {
        throw new SplunkMcpError("JOB_NOT_DONE", "The job is still running.", {
          meta: { sid: args.sid, done_progress: status.done_progress },
          hint: "Call splunk_get_job_status and wait until is_done is true.",
        });
      }
      const off = args.offset ?? 0;
      const limit = clampRows(args.max_rows, 100, config);
      const { rows, fetched, blocked } = await jobResults(client, args.sid, {
        offset: off,
        count: limit,
        fields: args.fields,
        blockedHosts: client.env.blockedHosts,
      });
      const more = off + fetched < status.result_count;
      return ok(
        {
          data: rows,
          meta: {
            environment: client.env.name,
            sid: args.sid,
            count: rows.length,
            total: status.result_count,
            offset: off,
            truncated: more,
            ...(more ? { next_offset: off + fetched } : {}),
            ...(blocked > 0 ? { blocked_rows: blocked } : {}),
          },
          hint:
            [more ? `More results available. Call again with offset=${off + fetched}.` : undefined, blockedNote(blocked)]
              .filter(Boolean)
              .join(" ") || undefined,
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_cancel_job",
    "Cancel a running search job that is no longer needed. Only affects the user's own search job, no data is changed.",
    { sid: z.string().describe("Search job id.") },
    async ({ sid }, { client }) => {
      assertOwnJob(sid, client.env.name);
      await client.post(`/services/search/v2/jobs/${enc(sid)}/control`, { action: "cancel" });
      return ok({ data: { sid, cancelled: true }, meta: { environment: client.env.name } }, config.maxOutputChars);
    },
  );

  tool(
    "splunk_validate_spl",
    "Check an SPL query without running it: first against this server's rules (event search only, no subsearches or macros, allowed commands), then for Splunk syntax. Use this before an expensive search or after an error.",
    { query: z.string().describe("SPL query to check."), app: appParam },
    async (args, { client }) => {
      validateQuery(args.query, client.env, config.redactor);
      const q = applyScope(args.query, client.env).query;
      const app = args.app ?? client.env.app;
      const call = (path: string) =>
        client.get<{ commands?: Array<{ command?: string }> }>(`/servicesNS/-/${enc(app)}/${path}`, {
          q,
          parse_only: true,
        });
      try {
        let res;
        try {
          res = await call("search/v2/parser");
        } catch (err) {
          if (err instanceof SplunkMcpError && err.code === "NOT_FOUND") res = await call("search/parser");
          else throw err;
        }
        return ok(
          {
            data: {
              valid: true,
              commands: (res.commands ?? []).map((c) => c.command).filter(Boolean),
              messages: [],
            },
            meta: { environment: client.env.name, effective_query: q },
          },
          config.maxOutputChars,
        );
      } catch (err) {
        if (err instanceof SplunkMcpError && err.code === "SPL_SYNTAX") {
          return ok(
            {
              data: { valid: false, commands: [], messages: err.splunkMessages },
              meta: { environment: client.env.name },
              hint: "Fix the query according to the Splunk messages.",
            },
            config.maxOutputChars,
          );
        }
        throw err;
      }
    },
  );

  // ---------------------------------------------------------------- 3.2 discovery
  tool(
    "splunk_list_indexes",
    "List the indexes the current user can see, with event counts and time coverage. Call this first when you do not know where the data lives.",
    {
      filter: z.string().optional().describe("Substring of the index name."),
      include_internal: z.boolean().optional().describe("Also list internal indexes (_internal, _audit, ...). Default false."),
    },
    async (args, { client }) => {
      const res = await client.get<Feed>("/services/data/indexes", { count: 0, datatype: "all" });
      const allowed = new Set(client.env.allowedIndexes.map((x) => x.toLowerCase()));
      const rows = (res.entry ?? [])
        .filter((e) => contains(e.name, args.filter))
        .filter((e) => args.include_internal || !e.name.startsWith("_"))
        .filter((e) => allowed.size === 0 || allowed.has(e.name.toLowerCase()))
        .map((e) => ({
          name: e.name,
          datatype: e.content?.datatype ?? "event",
          total_event_count: Number(e.content?.totalEventCount ?? 0),
          current_size_mb: Number(e.content?.currentDBSizeMB ?? 0),
          min_time: e.content?.minTime ?? null,
          max_time: e.content?.maxTime ?? null,
          disabled: truthy(e.content?.disabled),
        }))
        .sort((a, b) => b.total_event_count - a.total_event_count);
      return ok(
        {
          data: rows,
          meta: { environment: client.env.name, count: rows.length },
          hint: "Next: splunk_list_sourcetypes for an index to see which sourcetypes or hosts send data.",
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_list_sourcetypes",
    "List the sourcetypes or sources (log files) that the hosts of the environment send, with event counts and first/last time. Use this to find out which kinds of logs exist in an environment.",
    {
      index: z.string().optional().describe("Index name. Default: the environment's default index, otherwise the role's default indexes."),
      kind: z.enum(["sourcetypes", "sources"]).optional().describe("What to list. Default sourcetypes."),
      earliest: earliestParam("-7d"),
      max_rows: maxRows(100),
    },
    async (args, { client }) => {
      const kind = args.kind ?? "sourcetypes";
      const field = kind === "sourcetypes" ? "sourcetype" : "source";
      const index = args.index ?? client.env.defaultIndex;
      if (index) {
        assertIndexName(index);
        const allowed = client.env.allowedIndexes;
        if (allowed.length > 0 && !allowed.some((a) => a.toLowerCase() === index.toLowerCase())) {
          throw new SplunkMcpError("INDEX_NOT_ALLOWED", `Index not allowed in ${client.env.name}: ${index}.`, {
            hint: `Allowed indexes: ${allowed.join(", ")}.`,
          });
        }
      }
      const limit = clampRows(args.max_rows, 100, config);
      // Built by the server, not by the model: an indexed-field query limited to the environment's hosts.
      const where = [index ? `index=${quote(index)}` : undefined, hostClause(client.env.hosts), client.env.blockedHosts.length > 0 ? blockedClause(client.env.blockedHosts) : undefined]
        .filter(Boolean)
        .join(" ");
      const query = `| tstats count as totalCount min(_time) as firstTime max(_time) as lastTime where ${where} by ${field} | sort - totalCount | head ${limit}`;
      const earliest = args.earliest ?? "-7d";
      const { rows } = await runSearch(client, config, query, {
        earliest,
        latest: "now",
        app: client.env.app,
        maxRows: limit,
      });
      const data = rows.map((r) => ({
        name: r[field] ?? null,
        total_count: Number(r.totalCount ?? 0),
        first_time: isoTime(r.firstTime),
        last_time: isoTime(r.lastTime),
      }));
      return ok(
        {
          data,
          meta: { environment: client.env.name, hosts: client.env.hosts, kind, index: index ?? "(role default indexes)", earliest, count: data.length },
          hint: "Next: splunk_get_field_summary to see which fields the data has.",
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_field_summary",
    "Show which fields exist in the environment's data, how often they occur and example values. Use this before writing a search that filters or groups by fields you have not seen yet.",
    {
      index: z.string().optional().describe("Index name. Default: the environment's default index, otherwise the role's default indexes."),
      sourcetype: z.string().optional().describe("Default: the configured default sourcetype."),
      earliest: earliestParam("-1h"),
      sample_size: z.number().int().min(1).optional().describe("Number of events to sample. Default 5000."),
      max_fields: z.number().int().min(1).optional().describe("Maximum fields to return. Default 50."),
    },
    async (args, { client }) => {
      if (args.index) assertIndexName(args.index);
      const sample = Math.min(args.sample_size ?? 5000, 50000);
      const maxFields = Math.min(args.max_fields ?? 50, 200);
      if (args.sourcetype) validateQuery(`sourcetype=${quote(args.sourcetype)}`, client.env, config.redactor);
      if (args.index) validateQuery(`index=${args.index}`, client.env, config.redactor);
      const scoped = applyScope("", client.env, { index: args.index, sourcetype: args.sourcetype });
      const query = `${scoped.query} | head ${sample} | fieldsummary maxvals=5 | sort - count | head ${maxFields}`;
      const earliest = args.earliest ?? "-1h";
      const { rows } = await runSearch(client, config, query, {
        earliest,
        latest: "now",
        app: client.env.app,
        maxRows: maxFields,
      });
      const data = rows.map((r) => {
        let top: unknown = [];
        try {
          const parsed = JSON.parse(String(r.values ?? "[]")) as Array<{ value: unknown }>;
          top = parsed.slice(0, 5).map((v) => v.value);
        } catch {
          top = [];
        }
        const count = Number(r.count ?? 0);
        const fieldName = String(r.field ?? "");
        if (config.redactor?.isKeyName(fieldName) && Array.isArray(top)) {
          const red = config.redactor;
          top = (top as unknown[]).map((v) => red.pseudonym(red.keysMentioned(fieldName)[0] ?? fieldName, String(v)));
        }
        return {
          field: r.field,
          count,
          distinct_count: Number(r.distinct_count ?? 0),
          is_numeric: Number(r.numeric_count ?? 0) > count / 2,
          top_values: top,
        };
      });
      return ok(
        {
          data,
          meta: { environment: client.env.name, hosts: client.env.hosts, earliest, count: data.length, effective_query: query },
          hint: data.length === 0 ? "No events in this slice. Widen the time range or check the sourcetype." : undefined,
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_server_info",
    "Return Splunk version, server roles, license state and health. Use this to check connectivity or when behaviour depends on the Splunk version.",
    {},
    async (_args, { client }) => {
      const info = await client.get<Feed>("/services/server/info");
      const c = info.entry?.[0]?.content ?? {};
      let health: unknown = null;
      try {
        const h = await client.get<Feed>("/services/server/health/splunkd");
        health = h.entry?.[0]?.content?.health ?? null;
      } catch {
        health = "unavailable";
      }
      return ok(
        {
          data: {
            version: c.version ?? null,
            build: c.build ?? null,
            server_name: c.serverName ?? null,
            server_roles: c.server_roles ?? [],
            os_name: c.os_name ?? null,
            license_state: c.licenseState ?? null,
            kvstore_status: c.kvStoreStatus ?? null,
            health,
          },
          meta: { environment: client.env.name },
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_current_user",
    "Return the authenticated Splunk user with roles and capabilities. Use this to explain permission errors.",
    {},
    async (_args, { client }) => {
      const res = await client.get<Feed>("/services/authentication/current-context");
      const c = res.entry?.[0]?.content ?? {};
      return ok(
        {
          data: {
            username: c.username ?? null,
            realname: c.realname ?? null,
            roles: c.roles ?? [],
            default_app: c.defaultApp ?? null,
            capabilities: c.capabilities ?? [],
          },
          meta: { environment: client.env.name },
        },
        config.maxOutputChars,
      );
    },
  );

  // ---------------------------------------------------------------- 3.3 reports and alerts
  const isAlert = (c: Record<string, unknown>) =>
    (c.alert_type !== undefined && c.alert_type !== "always") || truthy(c["alert.track"]) || String(c.actions ?? "") !== "";

  tool(
    "splunk_list_saved_searches",
    "List saved searches (reports and alerts) with their schedule and owner. Use splunk_get_saved_search to see the SPL of one.",
    {
      filter: z.string().optional().describe("Substring of the name."),
      app: anyAppParam,
      only_alerts: z.boolean().optional().describe("Only entries with an alert condition or alert actions."),
      only_scheduled: z.boolean().optional().describe("Only scheduled searches."),
      max_rows: maxRows(50),
      offset,
    },
    async (args, { client }) => {
      const res = await client.get<Feed>(`/servicesNS/-/${enc(args.app ?? "-")}/saved/searches`, {
        count: 0,
        search: sanitizeFilter(args.filter),
      });
      const all = (res.entry ?? [])
        .filter((e) => contains(e.name, args.filter))
        .map((e) => {
          const c = e.content ?? {};
          return {
            name: e.name,
            app: e.acl?.app ?? null,
            owner: e.acl?.owner ?? null,
            is_scheduled: truthy(c.is_scheduled),
            cron_schedule: c.cron_schedule ?? null,
            is_alert: isAlert(c),
            disabled: truthy(c.disabled),
            next_scheduled_time: c.next_scheduled_time ?? null,
          };
        })
        .filter((r) => !args.only_alerts || r.is_alert)
        .filter((r) => !args.only_scheduled || r.is_scheduled);
      const off = args.offset ?? 0;
      const limit = clampRows(args.max_rows, 50, config);
      const page = all.slice(off, off + limit);
      const more = off + page.length < all.length;
      return ok(
        {
          data: page,
          meta: {
            environment: client.env.name,
            count: page.length,
            total: all.length,
            offset: off,
            truncated: more,
            ...(more ? { next_offset: off + page.length } : {}),
          },
          hint: more ? `More entries available. Call again with offset=${off + page.length} or use filter.` : undefined,
        },
        config.maxOutputChars,
      );
    },
  );

  async function loadSavedSearch(client: SplunkClient, name: string, app?: string): Promise<Entry> {
    const res = await client.get<Feed>(`/servicesNS/-/${enc(app ?? "-")}/saved/searches/${enc(name)}`);
    const entry = res.entry?.[0];
    if (!entry) {
      throw new SplunkMcpError("NOT_FOUND", `Saved search "${name}" not found.`, {
        hint: "Call splunk_list_saved_searches to get the exact name.",
      });
    }
    return entry;
  }

  tool(
    "splunk_get_saved_search",
    "Return the full definition of one saved search: SPL, time range, schedule, alert condition and actions.",
    { name: z.string().describe("Exact name of the saved search."), app: anyAppParam },
    async (args, { client }) => {
      const e = await loadSavedSearch(client, args.name, args.app);
      const c = e.content ?? {};
      return ok(
        {
          data: {
            name: e.name,
            app: e.acl?.app ?? null,
            owner: e.acl?.owner ?? null,
            description: c.description ?? "",
            search: c.search ?? "",
            earliest: c["dispatch.earliest_time"] ?? null,
            latest: c["dispatch.latest_time"] ?? null,
            is_scheduled: truthy(c.is_scheduled),
            cron_schedule: c.cron_schedule ?? null,
            disabled: truthy(c.disabled),
            is_alert: isAlert(c),
            alert_type: c.alert_type ?? null,
            alert_comparator: c.alert_comparator ?? null,
            alert_threshold: c.alert_threshold ?? null,
            alert_severity: c["alert.severity"] ?? null,
            actions: c.actions ?? "",
          },
          meta: { environment: client.env.name },
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_run_saved_search",
    "Run the SPL of an existing saved search now, limited to the hosts of the environment, and return the results. Alert actions are not triggered. Only works if the saved SPL is a plain event search (no leading pipe, subsearches, macros or commands that read other data).",
    {
      name: z.string().describe("Exact name of the saved search."),
      app: anyAppParam,
      earliest: z.string().optional().describe("Overrides the saved start of the time range."),
      latest: z.string().optional().describe("Overrides the saved end of the time range."),
      max_rows: maxRows(100),
    },
    async (args, { client }) => {
      const e = await loadSavedSearch(client, args.name, args.app);
      const spl = String(e.content?.search ?? "");
      // The stored SPL is never dispatched as is: it goes through the same checks
      // and gets the same mandatory host filter as a query written by the model.
      validateQuery(spl, client.env, config.redactor);
      const scoped = applyScope(spl, client.env);
      const earliest = args.earliest ?? String(e.content?.["dispatch.earliest_time"] || config.defaultEarliest);
      const latest = args.latest ?? String(e.content?.["dispatch.latest_time"] || "now");
      const limit = clampRows(args.max_rows, 100, config);
      const { sid, status, rows, fetched, blocked } = await runSearch(client, config, scoped.query, {
        earliest,
        latest,
        app: e.acl?.app ?? client.env.app,
        maxRows: limit,
      });
      const truncated = status.result_count > fetched;
      return ok(
        {
          data: rows,
          meta: {
            environment: client.env.name,
            sid,
            count: rows.length,
            total: status.result_count,
            offset: 0,
            truncated,
            run_duration_s: status.run_duration_s,
            earliest,
            latest,
            effective_query: scoped.query,
            hosts: client.env.hosts,
            ...(blocked > 0 ? { blocked_rows: blocked } : {}),
          },
          hint:
            [
              truncated
                ? `Showing ${fetched} of ${status.result_count} results. Call splunk_get_job_results with sid and offset=${fetched}.`
                : undefined,
              blockedNote(blocked),
            ]
              .filter(Boolean)
              .join(" ") || undefined,
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_list_fired_alerts",
    "List alerts that have triggered recently (names, counts, times only; the alert results themselves are not accessible). Without name: one row per alert with its trigger count. With name: the individual trigger events with time and severity.",
    {
      name: z.string().optional().describe("Alert name for the individual trigger events."),
      max_rows: maxRows(50),
    },
    async (args, { client }) => {
      const limit = clampRows(args.max_rows, 50, config);
      if (!args.name) {
        const res = await client.get<Feed>("/servicesNS/-/-/alerts/fired_alerts", { count: limit });
        const data = (res.entry ?? [])
          .filter((e) => e.name !== "-")
          .map((e) => ({ alert_name: e.name, triggered_count: Number(e.content?.triggered_alert_count ?? 0), app: e.acl?.app ?? null }));
        return ok(
          {
            data,
            meta: { environment: client.env.name, count: data.length },
            hint: data.length > 0 ? "Call again with name to see when and why an alert triggered." : "No alerts have triggered.",
          },
          config.maxOutputChars,
        );
      }
      const res = await client.get<Feed>(`/servicesNS/-/-/alerts/fired_alerts/${enc(args.name)}`, { count: limit });
      const data = (res.entry ?? []).map((e) => ({
        alert_name: e.content?.savedsearch_name ?? args.name,
        trigger_time: isoTime(e.content?.trigger_time),
        severity: e.content?.severity ?? null,
        triggered_count: Number(e.content?.triggered_alerts ?? 0),
        app: e.acl?.app ?? null,
      }));
      return ok({ data, meta: { environment: client.env.name, count: data.length } }, config.maxOutputChars);
    },
  );

  // ---------------------------------------------------------------- 3.4 knowledge objects
  const KO_PATHS = {
    macros: "configs/conf-macros",
    lookups: "data/transforms/lookups",
    datamodels: "datamodel/model",
    dashboards: "data/ui/views",
  } as const;

  function koSummary(type: string, c: Record<string, unknown>): string {
    switch (type) {
      case "macros":
        return c.args ? `args: ${String(c.args)}` : "no args";
      case "lookups":
        return String(c.filename ?? c.collection ?? c.external_cmd ?? c.type ?? "");
      case "datamodels":
        return String(c.displayName ?? "");
      case "dashboards":
        return String(c.label ?? "");
      case "apps":
        return `${String(c.label ?? "")} v${String(c.version ?? "?")}${truthy(c.disabled) ? " (disabled)" : ""}`;
      default:
        return "";
    }
  }

  tool(
    "splunk_list_knowledge_objects",
    "List Splunk knowledge objects of one type: macros, lookups, data models, dashboards or installed apps.",
    {
      type: z.enum(["macros", "lookups", "datamodels", "dashboards", "apps"]).describe("Kind of object to list."),
      filter: z.string().optional().describe("Substring of the name."),
      app: anyAppParam,
      max_rows: maxRows(50),
      offset,
    },
    async (args, { client }) => {
      const path =
        args.type === "apps" ? "/services/apps/local" : `/servicesNS/-/${enc(args.app ?? "-")}/${KO_PATHS[args.type]}`;
      const off = args.offset ?? 0;
      const limit = clampRows(args.max_rows, 50, config);
      const res = await client.get<Feed>(path, { count: limit, offset: off, search: sanitizeFilter(args.filter) });
      const data = (res.entry ?? [])
        .filter((e) => contains(e.name, args.filter))
        .map((e) => ({
          name: e.name,
          app: e.acl?.app ?? null,
          owner: e.acl?.owner ?? null,
          sharing: e.acl?.sharing ?? null,
          summary: koSummary(args.type, e.content ?? {}),
        }));
      const total = res.paging?.total ?? data.length;
      const more = off + data.length < total;
      return ok(
        {
          data,
          meta: {
            environment: client.env.name,
            type: args.type,
            count: data.length,
            total,
            offset: off,
            truncated: more,
            ...(more ? { next_offset: off + data.length } : {}),
          },
          hint: more ? `More entries available. Call again with offset=${off + data.length} or use filter.` : undefined,
        },
        config.maxOutputChars,
      );
    },
  );

  tool(
    "splunk_get_knowledge_object",
    "Return the full definition of one macro, lookup, data model or dashboard (configuration only, no data rows).",
    {
      type: z.enum(["macros", "lookups", "datamodels", "dashboards"]).describe("Kind of object."),
      name: z.string().describe("Exact name of the object."),
      app: anyAppParam,
    },
    async (args, { client }) => {
      const res = await client.get<Feed>(`/servicesNS/-/${enc(args.app ?? "-")}/${KO_PATHS[args.type]}/${enc(args.name)}`);
      const e = res.entry?.[0];
      if (!e) {
        throw new SplunkMcpError("NOT_FOUND", `${args.type} "${args.name}" not found.`, {
          hint: "Call splunk_list_knowledge_objects to get the exact name.",
        });
      }
      const c = e.content ?? {};
      let definition: Record<string, unknown>;
      switch (args.type) {
        case "macros":
          definition = { definition: c.definition ?? "", args: c.args ?? "", iseval: truthy(c.iseval), description: c.description ?? "" };
          break;
        case "lookups":
          definition = {
            type: c.type ?? null,
            filename: c.filename ?? null,
            collection: c.collection ?? null,
            fields_list: c.fields_list ?? null,
            match_type: c.match_type ?? null,
            external_cmd: c.external_cmd ?? null,
          };
          break;
        case "datamodels": {
          let objects: unknown = [];
          try {
            const model = JSON.parse(String(c.description ?? "{}")) as {
              objects?: Array<{ objectName?: string; parentName?: string; fields?: Array<{ fieldName?: string }>; constraints?: Array<{ search?: string }> }>;
            };
            objects = (model.objects ?? []).map((o) => ({
              name: o.objectName,
              parent: o.parentName,
              constraints: (o.constraints ?? []).map((x) => x.search),
              fields: (o.fields ?? []).map((f) => f.fieldName),
            }));
          } catch {
            objects = [];
          }
          definition = { display_name: c.displayName ?? null, acceleration: c.acceleration ?? null, objects };
          break;
        }
        case "dashboards":
          definition = { label: c.label ?? null, source: String(c["eai:data"] ?? "") };
          break;
      }
      return ok(
        {
          data: { name: e.name, app: e.acl?.app ?? null, owner: e.acl?.owner ?? null, ...definition },
          meta: { environment: client.env.name, type: args.type },
        },
        config.maxOutputChars,
      );
    },
  );

  // ---------------------------------------------------------------- 3.5 KV store
  if (config.enableKvstore)
  tool(
    "splunk_query_kvstore",
    "Read records from a KV store collection. Omit collection to list the collections of an app.",
    {
      app: appParam,
      collection: z.string().optional().describe("Collection name. Omit to list collections."),
      query: z.string().optional().describe('MongoDB-style filter as JSON string, e.g. {"status":"open"}.'),
      fields: z.array(z.string()).optional().describe("Return only these fields."),
      sort: z.string().optional().describe("Sort order, e.g. _key:1 (ascending) or updated:-1 (descending)."),
      max_rows: maxRows(100),
      offset,
    },
    async (args, { client }) => {
      const app = args.app ?? client.env.app;
      if (!args.collection) {
        const res = await client.get<Feed>(`/servicesNS/nobody/${enc(app)}/storage/collections/config`, { count: 0 });
        const data = (res.entry ?? []).map((e) => ({ name: e.name, app: e.acl?.app ?? null }));
        return ok({ data, meta: { environment: client.env.name, app, count: data.length } }, config.maxOutputChars);
      }
      if (args.query) {
        try {
          JSON.parse(args.query);
        } catch {
          throw new SplunkMcpError("INVALID_ARGUMENT", "query must be valid JSON.", { hint: 'Example: {"status":"open"}' });
        }
      }
      const off = args.offset ?? 0;
      const limit = clampRows(args.max_rows, 100, config);
      const rows = await client.get<Row[]>(
        `/servicesNS/nobody/${enc(app)}/storage/collections/data/${enc(args.collection)}`,
        { query: args.query, fields: args.fields?.join(","), sort: args.sort, limit, skip: off },
        true,
      );
      const all = Array.isArray(rows) ? rows : [];
      const { rows: data, blocked } = dropBlockedRows(all, client.env.blockedHosts);
      const maybeMore = all.length === limit;
      return ok(
        {
          data,
          meta: {
            environment: client.env.name,
            app,
            collection: args.collection,
            count: data.length,
            offset: off,
            truncated: maybeMore,
            ...(maybeMore ? { next_offset: off + all.length } : {}),
            ...(blocked > 0 ? { blocked_rows: blocked } : {}),
          },
          hint:
            [maybeMore ? `There may be more records. Call again with offset=${off + all.length}.` : undefined, blockedNote(blocked)]
              .filter(Boolean)
              .join(" ") || undefined,
        },
        config.maxOutputChars,
      );
    },
  );

}

export const SERVER_INSTRUCTIONS = `Read-only access to one self-hosted Splunk instance. An "environment" is a fixed set of hosts on that instance.

Rules:
- Every tool needs "environment". If the user did not name one, call splunk_list_environments and ask. Never guess, never switch environment on your own.
- Every search is automatically limited to the hosts of the chosen environment. This cannot be changed. Do not add host filters yourself.
- Some hosts are blocked because their data is confidential. If you get BLOCKED_HOST or QUERY_NOT_ALLOWED, do not look for another way to reach that data; tell the user.
- Write plain event searches: search terms, then pipes (stats, eval, where, rex, timechart, top, ...). No leading pipe, no subsearches in [ ], no macros, no append/join/tstats/inputlookup.
- Values like [lastName#3fa9c2d1] are pseudonyms for personal data: the same value always gives the same pseudonym, so you can count and correlate them, but the real value is not available. Do not try to recover it. Pseudonymised fields can be filtered and grouped (stats ... by), not copied, renamed or extracted.
- meta.effective_query shows the SPL that actually ran, including the default sourcetype and exclusion filters.
- Explore before guessing: splunk_list_sourcetypes shows which logs exist, splunk_get_field_summary shows the available fields.
- Always use a time range and aggregate in SPL instead of pulling raw events. Keep max_rows small.
- When meta.truncated is true the result is incomplete: narrow the search or page with splunk_get_job_results.
- A job id (sid) only works in the environment and session that created it.
- On AUTH_FAILED or LOGIN_BLOCKED stop and tell the user. Do not retry.`;
