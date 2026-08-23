// Copyright (C) 2026 Julian Pawlowski
// All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"use strict";

const {AREA_CHOICES} = require("./contribution-labels.js");

const LABEL = "needs revision";
const MARKER = "<!-- contribution-hygiene:issue -->";
const BOT = "github-actions[bot]";

function commentBody(result) {
  const details = result.problems.map((problem) => `- ${problem}`).join("\n");
  return `${MARKER}\nThis issue needs a small revision / Dieses Issue braucht eine kleine Überarbeitung.\n\n` +
    `Counted prose / Gezählte Prosa: **${result.word_count}/${result.limit}**\n\n${details}`;
}

async function markerComments(github, owner, repo, issueNumber) {
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner, repo, issue_number: issueNumber, per_page: 100,
  });
  return comments.filter((comment) => comment.user && comment.user.login === BOT && comment.body.includes(MARKER));
}

async function ensureLabel(github, owner, repo, name, definition) {
  try {
    await github.rest.issues.getLabel({owner, repo, name});
  } catch (error) {
    if (error.status !== 404) throw error;
    await github.rest.issues.createLabel({
      owner, repo, name, color: definition.color, description: definition.description,
    });
  }
}

function suggestedArea(body) {
  const match = String(body || "").match(/^#{2,6}\s+Suggested area\s*$\n+\s*([^\n]+?)\s*$/im);
  return match && AREA_CHOICES.has(match[1]) ? match[1] : "";
}

async function removeNamedLabel(github, owner, repo, issueNumber, name) {
  try {
    await github.rest.issues.removeLabel({owner, repo, issue_number: issueNumber, name});
  } catch (error) {
    if (error.status !== 404) throw error;
  }
}

async function applySuggestedArea(github, owner, repo, issue, previousBody = "") {
  const suggestion = suggestedArea(issue.body);
  const assigned = (issue.labels || []).map((label) => typeof label === "string" ? label : label.name);
  const assignedAreas = assigned.filter((label) => AREA_CHOICES.has(label));
  const previousSuggestion = suggestedArea(previousBody);
  const replacesAutomatedSuggestion = previousSuggestion && assignedAreas.length === 1 &&
    assignedAreas[0] === previousSuggestion && suggestion !== previousSuggestion;

  if (replacesAutomatedSuggestion) {
    await removeNamedLabel(github, owner, repo, issue.number, previousSuggestion);
  } else if (assignedAreas.length) {
    // An area that differs from the form's previous suggestion is a maintainer
    // decision. Automation never replaces it.
    return;
  }
  if (!suggestion) return;
  await ensureLabel(github, owner, repo, suggestion, AREA_CHOICES.get(suggestion));
  await github.rest.issues.addLabels({owner, repo, issue_number: issue.number, labels: [suggestion]});
}

async function removeLabel(github, owner, repo, issueNumber) {
  try {
    await github.rest.issues.removeLabel({owner, repo, issue_number: issueNumber, name: LABEL});
  } catch (error) {
    if (error.status !== 404) throw error;
  }
}

async function reconcile({github, context, result}) {
  const {owner, repo} = context.repo;
  const issue = context.payload.issue;
  const issueNumber = issue.number;

  // A closed conversation is not newly nagged. A compliant edit still reaches
  // the cleanup below and removes obsolete automation state.
  if (!result.valid && issue.state === "closed") return;

  // An outside contributor cannot apply labels directly. The form therefore
  // carries one allow-listed suggestion. Reconcile a known earlier suggestion,
  // but preserve a different area as a maintainer's decision.
  await applySuggestedArea(github, owner, repo, issue, context.payload.changes?.body?.from || "");

  const comments = await markerComments(github, owner, repo, issueNumber);
  if (result.valid) {
    await removeLabel(github, owner, repo, issueNumber);
    for (const comment of comments) {
      await github.rest.issues.deleteComment({owner, repo, comment_id: comment.id});
    }
    return;
  }

  await ensureLabel(github, owner, repo, LABEL, {
    color: "D93F0B", description: "The issue needs a small structural or length revision",
  });
  await github.rest.issues.addLabels({owner, repo, issue_number: issueNumber, labels: [LABEL]});
  const body = commentBody(result);
  if (comments.length) {
    if (comments[0].body !== body) {
      await github.rest.issues.updateComment({owner, repo, comment_id: comments[0].id, body});
    }
    for (const comment of comments.slice(1)) {
      await github.rest.issues.deleteComment({owner, repo, comment_id: comment.id});
    }
  } else {
    await github.rest.issues.createComment({owner, repo, issue_number: issueNumber, body});
  }
}

module.exports = {AREA_CHOICES, BOT, LABEL, MARKER, applySuggestedArea, commentBody, suggestedArea, reconcile};
