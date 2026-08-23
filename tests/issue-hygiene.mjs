// Copyright (C) 2026 Julian Pawlowski
// All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"use strict";

import assert from "node:assert/strict";
import hygiene from "../.github/scripts/issue-hygiene.js";

function fixture() {
  const state = {comments: [], labels: new Set(), calls: []};
  let nextId = 1;
  const record = (name, implementation = async () => ({})) => async (arguments_) => {
    state.calls.push([name, arguments_]);
    return implementation(arguments_);
  };
  const issues = {
    listComments: async () => state.comments,
    getLabel: record("getLabel", async ({name}) => {
      if (!state.labels.has(name)) throw Object.assign(new Error("missing"), {status: 404});
    }),
    createLabel: record("createLabel", async ({name}) => state.labels.add(name)),
    addLabels: record("addLabels", async ({labels}) => labels.forEach((label) => state.labels.add(label))),
    removeLabel: record("removeLabel", async ({name}) => {
      if (!state.labels.delete(name)) throw Object.assign(new Error("missing"), {status: 404});
    }),
    createComment: record("createComment", async ({body}) => {
      state.comments.push({id: nextId++, body, user: {login: hygiene.BOT}});
    }),
    updateComment: record("updateComment", async ({comment_id, body}) => {
      state.comments.find((comment) => comment.id === comment_id).body = body;
    }),
    deleteComment: record("deleteComment", async ({comment_id}) => {
      state.comments = state.comments.filter((comment) => comment.id !== comment_id);
    }),
  };
  return {
    state,
    github: {rest: {issues}, paginate: async (method, arguments_) => method(arguments_)},
    context: {repo: {owner: "owner", repo: "repo"}, payload: {
      issue: {number: 7, state: "open", body: "", labels: []},
    }},
  };
}

const invalid = {valid: false, word_count: 176, limit: 175, problems: ["too long"]};
const valid = {valid: true, word_count: 20, limit: 175, problems: []};

const first = fixture();
first.state.comments.push({id: 99, body: hygiene.MARKER, user: {login: "a-person"}});
await hygiene.reconcile({...first, result: invalid});
assert(first.state.labels.has(hygiene.LABEL));
assert.equal(first.state.comments.filter((comment) => comment.user.login === hygiene.BOT).length, 1);
assert(first.state.comments.some((comment) => comment.id === 99), "a user's copied marker must remain");

await hygiene.reconcile({...first, result: {...invalid, word_count: 180}});
assert.equal(first.state.comments.filter((comment) => comment.user.login === hygiene.BOT).length, 1,
  "a repeated failure updates instead of duplicating the bot comment");

first.state.comments.push({id: 100, body: hygiene.MARKER, user: {login: hygiene.BOT}});
await hygiene.reconcile({...first, result: valid});
assert(!first.state.labels.has(hygiene.LABEL));
assert.equal(first.state.comments.filter((comment) => comment.user.login === hygiene.BOT).length, 0,
  "all obsolete bot marker comments are removed");
assert(first.state.comments.some((comment) => comment.id === 99), "user comments are never removed");

const closed = fixture();
closed.context.payload.issue.state = "closed";
await hygiene.reconcile({...closed, result: invalid});
assert.equal(closed.state.calls.length, 0, "a closed invalid issue is not newly nagged");

const suggested = fixture();
suggested.context.payload.issue.body = "### Suggested area\n\narea: contribution\n\n### TL;DR\n\nShort.";
await hygiene.reconcile({...suggested, result: valid});
assert(suggested.state.labels.has("area: contribution"), "an allow-listed suggestion becomes an area label");

const maintained = fixture();
maintained.context.payload.issue.body = suggested.context.payload.issue.body;
maintained.context.payload.issue.labels = [{name: "area: oidc"}];
await hygiene.reconcile({...maintained, result: valid});
assert(!maintained.state.calls.some(([name, arguments_]) =>
  name === "addLabels" && arguments_.labels.includes("area: contribution")),
"automation does not overwrite a maintainer-assigned area");

const revised = fixture();
revised.context.payload.issue.body = "### Suggested area\n\narea: ui\n\n### TL;DR\n\nShort.";
revised.context.payload.issue.labels = [{name: "area: contribution"}];
revised.context.payload.changes = {body: {from: suggested.context.payload.issue.body}};
revised.state.labels.add("area: contribution");
await hygiene.reconcile({...revised, result: valid});
assert(!revised.state.labels.has("area: contribution"), "the obsolete automated suggestion is removed");
assert(revised.state.labels.has("area: ui"), "a contributor can revise an automated area suggestion");

const revisedAfterMaintenance = fixture();
revisedAfterMaintenance.context.payload.issue.body = revised.context.payload.issue.body;
revisedAfterMaintenance.context.payload.issue.labels = [{name: "area: oidc"}];
revisedAfterMaintenance.context.payload.changes = {body: {from: suggested.context.payload.issue.body}};
revisedAfterMaintenance.state.labels.add("area: oidc");
await hygiene.reconcile({...revisedAfterMaintenance, result: valid});
assert(revisedAfterMaintenance.state.labels.has("area: oidc"), "a maintainer area survives a form edit");
assert(!revisedAfterMaintenance.state.labels.has("area: ui"), "a form edit does not replace maintainer choice");

console.log("10 issue hygiene checks passed");
