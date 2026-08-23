// Copyright (C) 2026 Julian Pawlowski
// All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"use strict";

const AREA_CHOICES = new Map([
  ["area: oidc", {color: "1D76DB", description: "OpenID Connect protocol, tokens, claims, and sessions"}],
  ["area: opnsense", {color: "5319E7", description: "OPNsense core and WebGUI integration"}],
  ["area: ui", {color: "C5DEF5", description: "Contributor-facing or operator-facing user interface"}],
  ["area: packaging", {color: "0E8A16", description: "Package, build, release, and distribution"}],
  ["area: contribution", {
    color: "FBCA04", description: "Contribution guidance, GitHub automation, and community process",
  }],
]);

const CHANGE_CHOICES = new Map([
  ["change: feature", {color: "A2EEEF", description: "Adds user-visible capability"}],
  ["change: fix", {color: "D73A4A", description: "Corrects unintended behavior"}],
  ["change: performance", {color: "FBCA04", description: "Improves runtime performance"}],
  ["change: docs", {color: "0075CA", description: "Changes documentation only"}],
  ["change: maintenance", {color: "CFD3D7", description: "Internal, test, build, or pipeline maintenance"}],
]);

const BREAKING_LABEL = "impact: breaking";
const BREAKING_DEFINITION = {
  color: "B60205", description: "Requires an explicit operator action when upgrading",
};
const ISSUE_TYPES = new Set(["type: bug", "type: change", "type: docs", "type: question"]);
const COMMIT_CHANGES = new Map([
  ["feat", "change: feature"],
  ["fix", "change: fix"],
  ["perf", "change: performance"],
  ["docs", "change: docs"],
  ["refactor", "change: maintenance"],
  ["build", "change: maintenance"],
  ["ci", "change: maintenance"],
  ["test", "change: maintenance"],
  ["chore", "change: maintenance"],
  ["style", "change: maintenance"],
  ["revert", "change: maintenance"],
]);

function names(labels) {
  return (labels || []).map((label) => typeof label === "string" ? label : label.name);
}

function sections(body) {
  const clean = String(body || "").replace(/<!--.*?-->/gs, "");
  const heading = /^#{2,6}\s+(.+?)\s*$/gm;
  const matches = [...clean.matchAll(heading)];
  return new Map(matches.map((match, index) => {
    const end = index + 1 < matches.length ? matches[index + 1].index : clean.length;
    return [match[1].trim(), clean.slice(match.index + match[0].length, end).trim()];
  }));
}

function issueNumber(body) {
  const match = sections(body).get("Issue")?.match(/^Fixes\s+#([1-9]\d*)$/i);
  return match ? Number(match[1]) : null;
}

function titleClassification(title) {
  const match = String(title || "").match(/^([a-z]+)(?:\([^()\r\n]+\))?(!)?: /);
  return {
    change: match ? COMMIT_CHANGES.get(match[1]) || "" : "",
    breaking: Boolean(match && match[2]),
  };
}

function requestedAreas(body, issueLabels = []) {
  const value = sections(body).get("Area") || "";
  if (value === "Same as issue") {
    return names(issueLabels).filter((name) => AREA_CHOICES.has(name)).slice(0, 2);
  }
  const requested = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  return requested.length >= 1 && requested.length <= 2 && requested.every((name) => AREA_CHOICES.has(name))
    ? [...new Set(requested)] : [];
}

async function removeLabel(github, owner, repo, issueNumber, name) {
  try {
    await github.rest.issues.removeLabel({owner, repo, issue_number: issueNumber, name});
  } catch (error) {
    if (error.status !== 404) throw error;
  }
}

async function reconcilePullRequest({github, context}) {
  const {owner, repo} = context.repo;
  const request = context.payload.pull_request;
  const number = request.number;
  const assigned = new Set(names(request.labels));
  const reference = issueNumber(request.body);
  let issueLabels = [];
  if (reference !== null) {
    const issue = await github.rest.issues.get({owner, repo, issue_number: reference});
    if (!issue.data.pull_request) issueLabels = issue.data.labels || [];
  }

  const classification = titleClassification(request.title);
  const remove = new Set();
  const add = new Set();
  for (const label of assigned) {
    if (ISSUE_TYPES.has(label)) remove.add(label);
    if (CHANGE_CHOICES.has(label) && label !== classification.change) remove.add(label);
  }
  if (classification.change && !assigned.has(classification.change)) add.add(classification.change);

  if (classification.breaking && !assigned.has(BREAKING_LABEL)) add.add(BREAKING_LABEL);
  if (!classification.breaking && assigned.has(BREAKING_LABEL)) remove.add(BREAKING_LABEL);

  const areas = requestedAreas(request.body, issueLabels);
  if (areas.length) {
    for (const label of assigned) {
      if (AREA_CHOICES.has(label) && !areas.includes(label)) remove.add(label);
    }
    for (const label of areas) {
      if (!assigned.has(label)) add.add(label);
    }
  }

  const issueNeedsAccessibility = names(issueLabels).includes("accessibility");
  if (issueNeedsAccessibility && !assigned.has("accessibility")) add.add("accessibility");
  if (!issueNeedsAccessibility && assigned.has("accessibility")) remove.add("accessibility");
  for (const label of remove) await removeLabel(github, owner, repo, number, label);
  if (add.size) {
    await github.rest.issues.addLabels({owner, repo, issue_number: number, labels: [...add]});
  }
}

module.exports = {
  AREA_CHOICES,
  BREAKING_DEFINITION,
  BREAKING_LABEL,
  CHANGE_CHOICES,
  COMMIT_CHANGES,
  ISSUE_TYPES,
  issueNumber,
  requestedAreas,
  reconcilePullRequest,
  sections,
  titleClassification,
};
