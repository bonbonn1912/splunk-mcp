import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { fail, ok, setRedactor } from "../dist/format.js";
import { registerJob, jobResults } from "../dist/search.js";
import { Redactor } from "../dist/redact.js";
import { SplunkMcpError } from "../dist/errors.js";

const outputText = (result) => result.content[0].text;

afterEach(() => setRedactor(undefined));

test("ok redacts data, metadata, messages and hints, and omits encoded search URLs", () => {
  const redactor = new Redactor({ keys: ["lastName"] });
  setRedactor(redactor);

  const result = ok(
    {
      data: [{ lastName: "Mustermann" }],
      meta: {
        effective_query: 'search lastName="Mustermann"',
        splunk_messages: ['{"lastName":"Mustermann"}'],
        web_url: "https://splunk.example/search?q=" + encodeURIComponent('search lastName="Mustermann"'),
        sid: "job-123",
        environment: "test",
        count: 1,
      },
      hint: "Review Mustermann in the search output.",
    },
    10000,
  );
  const text = outputText(result);
  const parsed = JSON.parse(text);

  assert.equal(text.includes("Mustermann"), false);
  assert.equal("web_url" in parsed.meta, false);
  assert.equal(parsed.meta.sid, "job-123");
  assert.equal(parsed.meta.environment, "test");
  assert.equal(parsed.meta.count, 1);
  assert.match(parsed.data[0].lastName, /^\[lastName#[0-9a-f]{8}\]$/);
});

test("fail redacts error, Splunk messages, metadata and hint", () => {
  const redactor = new Redactor({ keys: ["lastName"] });
  setRedactor(redactor);

  const result = fail(
    new SplunkMcpError("SPLUNK_ERROR", "Rejected lastName=Mustermann", {
      splunkMessages: ['{"lastName":"Mustermann"}'],
      meta: { environment: "test", detail: "Mustermann" },
      hint: "Check Mustermann and retry.",
    }),
  );
  const text = outputText(result);
  const parsed = JSON.parse(text);

  assert.equal(result.isError, true);
  assert.equal(text.includes("Mustermann"), false);
  assert.equal(parsed.meta.environment, "test");
  assert.match(parsed.error.message, /\[lastName#[0-9a-f]{8}\]/);
});

test("hints introduced during size truncation are also redacted", () => {
  setRedactor(new Redactor({ keys: ["lastName"] }));
  const text = outputText(ok({ data: [{ padding: "x".repeat(2000) }] }, 300, "Check lastName=Mustermann"));
  const result = JSON.parse(text);
  assert.equal(result.meta.truncated, true);
  assert.equal(text.includes("Mustermann"), false);
  assert.match(result.hint, /\[lastName#[0-9a-f]{8}\]/);
});

test("job results redact complete raw rows before the 2000 character shortening", async () => {
  setRedactor(new Redactor({ keys: ["lastName"] }));
  registerJob("job-cutoff", "test");
  // The original raw cutoff removed the closing quote of this protected
  // value, causing redactJson to skip it and expose its visible prefix.
  const raw = '{"padding":"' + "x".repeat(1940) + '","lastName":"Mustermann' + "a".repeat(100) + '","tail":"' + "x".repeat(500) + '"}';
  const client = {
    env: { name: "test" },
    async get() {
      return { results: [{ _raw: raw, host: "allowed.example" }] };
    },
  };

  const result = await jobResults(client, "job-cutoff", {
    offset: 0,
    count: 10,
    blockedHosts: [],
  });
  const text = JSON.stringify(result.rows);

  assert.equal(text.includes("Mustermann"), false);
  assert.match(result.rows[0]._raw, /\[lastName#[0-9a-f]{8}\]/);
  assert.match(result.rows[0]._raw, /more chars/);
});

test("job results learn from unselected fields and scrub earlier rows in a two-pass scan", async () => {
  setRedactor(new Redactor({ keys: ["lastName"] }));
  registerJob("job-fields", "test");
  const client = {
    env: { name: "test" },
    async get() {
      return {
        results: [
          { _raw: "event for Mustermann", host: "allowed.example" },
          { _raw: "another event for Mustermann", lastName: "Mustermann", host: "allowed.example" },
        ],
      };
    },
  };

  const result = await jobResults(client, "job-fields", {
    offset: 0,
    count: 10,
    fields: ["_raw"],
    blockedHosts: [],
  });

  assert.equal(result.rows.length, 2);
  assert.equal(JSON.stringify(result.rows).includes("Mustermann"), false);
  assert.match(result.rows[0]._raw, /\[lastName#[0-9a-f]{8}\]/);
  assert.equal("lastName" in result.rows[1], false);
});

test("redaction remains disabled when no redactor is configured", () => {
  const webUrl = "https://splunk.example/search?q=lastName%3DMustermann";
  const result = ok({ data: [{ lastName: "Mustermann" }], meta: { web_url: webUrl } }, 10000);
  const parsed = JSON.parse(outputText(result));
  assert.equal(parsed.data[0].lastName, "Mustermann");
  assert.equal(parsed.meta.web_url, webUrl);
});

test("server job controls survive learned-value collisions while result fields stay redacted", () => {
  const redactor = new Redactor({ keys: ["customerId", "code"] });
  redactor.apply({ customerId: "12345" });
  setRedactor(redactor);
  const sid = "1727950000.12345";
  const result = JSON.parse(outputText(ok({
    data: { sid, note: "12345" },
    controlDataKeys: ["sid"],
    meta: { sid, environment: "TEST12345", offset: 0, next_offset: 1, count: 1, total: 2 },
  }, 10000)));
  assert.equal(result.data.sid, sid);
  assert.equal(result.meta.sid, sid);
  assert.equal(result.meta.environment, "TEST12345");
  assert.equal(result.meta.next_offset, 1);
  assert.match(result.data.note, /^\[customerId#[0-9a-f]{8}\]$/);

  const row = JSON.parse(outputText(ok({ data: [{ sid, web_url: "https://intranet/app", customerId: "12345" }] }, 10000)));
  assert.equal(row.data[0].web_url, "https://intranet/app");
  assert.notEqual(row.data[0].sid, sid);
  assert.match(row.data[0].sid, /\[customerId#[0-9a-f]{8}\]/);
  const error = JSON.parse(outputText(fail(new SplunkMcpError("TIMEOUT", "customerId=12345", { meta: { sid } }))));
  assert.equal(error.error.code, "TIMEOUT");
  assert.equal(error.meta.sid, sid);
  assert.match(error.error.message, /\[customerId#[0-9a-f]{8}\]/);
});

test("blocked rows are removed before redaction masks their host", async () => {
  setRedactor(new Redactor({ keys: ["host"] }));
  registerJob("job-blocked", "test");
  const client = {
    env: { name: "test" },
    async get() {
      return { results: [{ host: "prod-host", message: "confidential" }, { host: "test-host", message: "visible" }] };
    },
  };
  const result = await jobResults(client, "job-blocked", { offset: 0, count: 10, blockedHosts: ["prod-host"] });
  assert.equal(result.fetched, 2);
  assert.equal(result.blocked, 1);
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].message, "visible");
  assert.match(result.rows[0].host, /^\[host#[0-9a-f]{8}\]$/);
});
