import test from "node:test";
import assert from "node:assert/strict";
import { Redactor } from "../dist/redact.js";
import { allowedIndexClause, applyScope, validateQuery } from "../dist/spl.js";

const env = (overrides = {}) => ({
  name: "TEST",
  description: "",
  hosts: ["test-host"],
  blockedHosts: ["prod-host"],
  isProtected: false,
  app: "search",
  defaultSourcetype: undefined,
  defaultIndex: undefined,
  allowedIndexes: ["allowed"],
  excludeActuator: false,
  excludeTerms: [],
  ...overrides,
});

const redactor = new Redactor({ keys: ["lastName"] });

test("pseudonymisation rejects wildcard moves and field extraction", () => {
  for (const query of [
    "* | rename last* AS public* | table publicName",
    '* | rename "last*" AS "public*" | table publicName',
    "* | rename '*Name' AS 'public*' | table publicName",
    "* | stats values(last*) AS publicName",
    '* | stats values("last*") AS publicName',
    '* | stats list("last*") AS publicName',
    '* | chart values("last*") by logger',
    '* | timechart values("last*")',
    '* | convert ctime("last*") AS public',
    "* | addtotals fieldname=public | table public",
    "* | addcoltotals labelfield=public",
    "* | timewrap 1d",
    "* | tags outputfield=t inclvalue=t",
    "* | rex field=* \"(?<publicName>.*)\"",
    '* | spath output="publicName" path="last*"',
  ]) {
    assert.throws(() => validateQuery(query, env(), redactor), { code: "QUERY_NOT_ALLOWED" }, query);
  }
  assert.throws(() => validateQuery("* | transpose", env(), redactor), { code: "QUERY_NOT_ALLOWED" });
  assert.throws(() => validateQuery("* | eval publicName=lastName", env(), redactor), { code: "QUERY_NOT_ALLOWED" });
});

test("safe named grouping and aggregations remain available with pseudonymisation", () => {
  assert.doesNotThrow(() => validateQuery("error | stats count by host", env(), redactor));
  assert.doesNotThrow(() => validateQuery("error | stats count by lastName", env(), redactor));
  assert.doesNotThrow(() => validateQuery('* | eval note="literal*value" | stats count', env(), redactor));
  assert.doesNotThrow(() => validateQuery("* | stats count(*)", env(), redactor));
  assert.doesNotThrow(() => validateQuery('* | rex field=_raw "(?<status>OK|ERROR)"', env(), redactor));
  assert.doesNotThrow(() => validateQuery("* | stats values(eval(bytes*8)) by host", env(), redactor));
  assert.doesNotThrow(() => validateQuery("* | stats sum(eval(bytes*8)) by lastName", env(), redactor));
  assert.throws(() => validateQuery("* | stats values(eval(lastName*8)) by host", env(), redactor), { code: "QUERY_NOT_ALLOWED" });
  assert.doesNotThrow(() => validateQuery("* | eval scaled=bytes*8", env(), redactor));
  assert.doesNotThrow(() => validateQuery("* | stats sum(eval('byte-count'*8)) by host", env(), redactor));
  assert.throws(() => validateQuery('* | stats sum(eval(bytes*8)), list("last*") AS public', env(), redactor), { code: "QUERY_NOT_ALLOWED" });
  assert.throws(() => validateQuery("* | fields customerId | addtotals fieldname=public | table public", env(), new Redactor({ keys: ["customerId"] })), { code: "QUERY_NOT_ALLOWED" });
});

test("single-quoted field parentheses cannot hide sibling wildcard aggregates", () => {
  for (const query of [
    "x | stats sum(eval('((' + 1)) values(last*) AS pub* sum(eval('))' + 1))",
    "x | chart sum(eval('((' + 1)) values(last*) AS pub* sum(eval('))' + 1)) by host",
  ]) {
    assert.throws(() => validateQuery(query, env(), redactor), { code: "QUERY_NOT_ALLOWED" }, query);
  }
});

test("lookup is rejected as a query command", () => {
  assert.throws(() => validateQuery("* | lookup local_users username OUTPUT lastName", env()), { code: "QUERY_NOT_ALLOWED" });
});

test("lookup() function cannot read lookup data, while quoted text is harmless", () => {
  for (const query of [
    '* | eval x=lookup("customers.csv",json_object("id",id),json_array("secret"))',
    "* | where isnotnull(lookup('customers.csv',json_object('id',id),json_array('secret'))) ",
    '* | stats values(eval(lookup("customers.csv",json_object("id",id),json_array("secret"))))',
  ]) {
    assert.throws(() => validateQuery(query, env()), { code: "QUERY_NOT_ALLOWED" }, query);
  }
  assert.doesNotThrow(() => validateQuery('* | eval note="lookup(customers.csv)"', env()));
});

test("allowlisted indexes are always positively constrained", () => {
  const configured = env({ allowedIndexes: ["allowed", "also_allowed"] });
  const scoped = applyScope("*", configured).query;
  assert.match(scoped, /^search index IN \("allowed", "also_allowed"\) /);
  assert.match(scoped, /host="test-host"/);
  assert.match(scoped, /\(\*\)$/);
  assert.equal(allowedIndexClause(configured), 'index IN ("allowed", "also_allowed")');

  for (const bypass of ["index!=allowed", "NOT index=allowed", "*"]) {
    validateQuery(bypass, configured);
    assert.match(applyScope(bypass, configured).query, /^search index IN \("allowed", "also_allowed"\) /);
  }
  assert.throws(() => validateQuery("index=secret", configured), { code: "INDEX_NOT_ALLOWED" });
  assert.match(applyScope("index=allowed", configured).query, /^search index IN \("allowed", "also_allowed"\).*\(index=allowed\)$/);
});

test("empty allowlist leaves role index selection unchanged", () => {
  const unbounded = env({ allowedIndexes: [], defaultIndex: "role_default" });
  assert.equal(allowedIndexClause(unbounded), undefined);
  assert.match(applyScope("*", unbounded).query, /^search index="role_default" /);
  assert.doesNotMatch(applyScope("*", env({ allowedIndexes: [] })).query, /index IN/);
});
