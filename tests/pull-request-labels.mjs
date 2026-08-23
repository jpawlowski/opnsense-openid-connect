// Copyright (C) 2026 Julian Pawlowski
// All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"use strict";

import assert from "node:assert/strict";
import labels from "../.github/scripts/contribution-labels.js";

function fixture({title, body, assigned = [], issue = []}) {
  const state = new Set(assigned);
  const issues = {
    get: async () => ({data: {labels: issue}}),
    removeLabel: async ({name}) => state.delete(name),
    addLabels: async ({labels: additions}) => additions.forEach((name) => state.add(name)),
  };
  return {
    state,
    github: {rest: {issues}},
    context: {repo: {owner: "owner", repo: "repo"}, payload: {pull_request: {
      number: 7, title, body, labels: assigned.map((name) => ({name})),
    }}},
  };
}

const inherited = fixture({
  title: "feat(auth): add a bounded option",
  body: "## Issue\n\nFixes #42\n\n## Area\n\nSame as issue",
  assigned: ["type: change", "area: ui"],
  issue: [{name: "type: change"}, {name: "area: oidc"}, {name: "needs decision"}],
});
await labels.reconcilePullRequest(inherited);
assert(inherited.state.has("change: feature"));
assert(inherited.state.has("area: oidc"));
assert(!inherited.state.has("area: ui"));
assert(!inherited.state.has("type: change"));
assert(!inherited.state.has("needs decision"), "issue workflow labels are not copied");

const explicit = fixture({
  title: "fix(contribution)!: make the contract explicit",
  body: "## Issue\n\nNone\n\n## Area\n\narea: contribution",
  assigned: ["change: maintenance", "area: oidc"],
});
await labels.reconcilePullRequest(explicit);
assert(explicit.state.has("change: fix"));
assert(explicit.state.has("impact: breaking"));
assert(explicit.state.has("area: contribution"));
assert(!explicit.state.has("change: maintenance"));

assert.deepEqual(labels.requestedAreas("## Area\n\narea: oidc\narea: ui"), ["area: oidc", "area: ui"]);
assert.deepEqual(labels.requestedAreas("## Area\n\narea: unknown"), []);
assert.equal(labels.titleClassification("docs: explain labels").change, "change: docs");
assert.equal(labels.titleClassification("not a title").change, "");

console.log("13 pull request label checks passed");
