import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../dist/config.js";
import { registerTools } from "../dist/tools.js";
import { setRedactor } from "../dist/format.js";
import { Redactor } from "../dist/redact.js";

function harness() {
  const config = loadConfig({
    SPLUNK_URL: "https://splunk.invalid:8089",
    SPLUNK_TOKEN: "test-only-token",
    SPLUNK_HOST_TEST: "testhost01",
    SPLUNK_BLOCKED_HOSTS: "prodhost01",
    SPLUNK_ALLOWED_INDEXES: "allowed,logs",
  });
  const tools = new Map();
  const dispatched = [];
  const client = {
    env: config.environments.get("TEST"),
    username: async () => "test-user",
    post: async (_path, form) => {
      dispatched.push(form.search);
      return { sid: `security-test-${dispatched.length}` };
    },
    get: async (path) => {
      if (path.includes("/saved/searches/")) {
        return { entry: [{ name: "report", content: { search: "index!=allowed" } }] };
      }
      if (path.endsWith("/results")) return { results: [] };
      return { entry: [{ content: { isDone: true, resultCount: 0 } }] };
    },
  };
  registerTools(
    { registerTool: (name, _options, handler) => tools.set(name, handler) },
    config,
    { get: () => client, connection: { sessionState: "none" } },
  );
  return {
    dispatched,
    call: async (name, args = {}) => {
      const result = await tools.get(name)({ environment: "TEST", ...args });
      return JSON.parse(result.content[0].text);
    },
  };
}

test("all search tools dispatch with a mandatory positive index allowlist", async () => {
  const h = harness();
  for (const [tool, args] of [
    ["splunk_search", { query: "index!=allowed" }],
    ["splunk_start_search", { query: "NOT index=allowed" }],
    ["splunk_run_saved_search", { name: "report" }],
    ["splunk_get_field_summary", {}],
    ["splunk_list_sourcetypes", {}],
  ]) {
    const result = await h.call(tool, args);
    assert.equal(result.ok, true, `${tool}: ${JSON.stringify(result)}`);
    const query = h.dispatched.at(-1);
    assert.match(query, /index\s+IN\s*\(\s*"allowed"\s*,\s*"logs"\s*\)/i, tool);
    assert.match(query, /host="testhost01"/i, tool);
    assert.match(query, /NOT host="prodhost01"/i, tool);
  }
  assert.equal(h.dispatched.length, 5);
});

test("search tools reject lookup access and forbidden indexes before dispatch", async () => {
  const h = harness();
  for (const tool of ["splunk_search", "splunk_start_search", "splunk_validate_spl"]) {
    const lookup = await h.call(tool, { query: '* | eval key="demo" | lookup customer_table key OUTPUT secret | table secret' });
    assert.equal(lookup.ok, false);
    assert.equal(lookup.error.code, "QUERY_NOT_ALLOWED");
    const lookupFunction = await h.call(tool, { query: '* | eval x=lookup("customers.csv",json_object("id",id),json_array("secret"))' });
    assert.equal(lookupFunction.ok, false);
    assert.equal(lookupFunction.error.code, "QUERY_NOT_ALLOWED");
    const index = await h.call(tool, { query: "index=confidential" });
    assert.equal(index.ok, false);
    assert.equal(index.error.code, "INDEX_NOT_ALLOWED");
  }
  assert.deepEqual(h.dispatched, []);
});

test("job tools retain usable ids when learned private values overlap their sid", async () => {
  const redactor = new Redactor({ keys: ["customerId"] });
  redactor.apply({ customerId: "test" });
  setRedactor(redactor);
  try {
    const h = harness();
    const started = await h.call("splunk_start_search", { query: "*" });
    assert.equal(started.ok, true);
    const sid = started.data.sid;
    assert.equal(sid, "security-test-1");
    const status = await h.call("splunk_get_job_status", { sid });
    assert.equal(status.ok, true);
    assert.equal(status.data.sid, sid);
    const results = await h.call("splunk_get_job_results", { sid });
    assert.equal(results.ok, true);
    assert.equal(results.meta.sid, sid);
    const cancelled = await h.call("splunk_cancel_job", { sid });
    assert.equal(cancelled.ok, true);
    assert.equal(cancelled.data.sid, sid);
  } finally {
    setRedactor(undefined);
  }
});
