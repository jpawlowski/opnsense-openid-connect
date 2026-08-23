// Copyright (C) 2026 Julian Pawlowski
// All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"use strict";

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

async function ensureLabel(github, owner, repo) {
  try {
    await github.rest.issues.getLabel({owner, repo, name: LABEL});
  } catch (error) {
    if (error.status !== 404) throw error;
    await github.rest.issues.createLabel({
      owner, repo, name: LABEL, color: "D93F0B",
      description: "The issue needs a small structural or length revision",
    });
  }
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

  const comments = await markerComments(github, owner, repo, issueNumber);
  if (result.valid) {
    await removeLabel(github, owner, repo, issueNumber);
    for (const comment of comments) {
      await github.rest.issues.deleteComment({owner, repo, comment_id: comment.id});
    }
    return;
  }

  await ensureLabel(github, owner, repo);
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

module.exports = {BOT, LABEL, MARKER, commentBody, reconcile};
