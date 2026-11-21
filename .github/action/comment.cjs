"use strict";

const fs = require("fs");

/**
 * Posts or updates a sticky PR comment identified by COMMENT_MARKER using the
 * markdown payload at COMMENT_BODY_FILE. Gracefully skips on fork PR 403 errors.
 *
 * @param {object} params
 * @param {object} params.github - Octokit REST client provided by actions/github-script
 * @param {object} params.context - GitHub Actions workflow context
 * @param {object} params.core - @actions/core logger
 * @returns {Promise<{action: string, comment_id?: number}>}
 */
async function postStickyComment({ github, context, core }) {
  const issueNumber =
    (context && context.payload && context.payload.pull_request && context.payload.pull_request.number) ||
    (context && context.issue && context.issue.number);

  if (!issueNumber) {
    if (core && typeof core.info === "function") {
      core.info("No pull request number in context; skipping sticky PR comment.");
    }
    return { action: "skipped" };
  }

  const bodyFile = process.env.COMMENT_BODY_FILE || "";
  const marker = (process.env.COMMENT_MARKER || "").trim();
  if (!bodyFile || !marker) {
    throw new Error("COMMENT_BODY_FILE and COMMENT_MARKER environment variables are required.");
  }

  const body = fs.readFileSync(bodyFile, "utf8");
  if (!body || body.trim().length === 0) {
    throw new Error(`Sticky comment body file is empty: ${bodyFile}`);
  }

  const owner = context && context.repo && context.repo.owner;
  const repo = context && context.repo && context.repo.repo;
  if (!owner || !repo) {
    throw new Error("context.repo.owner and context.repo.repo are required.");
  }

  try {
    const comments = await github.paginate(github.rest.issues.listComments, {
      owner,
      repo,
      issue_number: issueNumber,
      per_page: 100,
    });

    const existing = comments.find(
      (c) =>
        c &&
        typeof c.body === "string" &&
        c.body.trimStart().startsWith(marker) &&
        c.user &&
        (c.user.type === "Bot" || c.user.login === "github-actions[bot]")
    );

    if (existing) {
      await github.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existing.id,
        body,
      });
      if (core && typeof core.info === "function") {
        core.info(`Updated sticky PR comment ${existing.id} for marker ${marker}.`);
      }
      return { action: "updated", comment_id: existing.id };
    }

    const created = await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
    const createdId = created && created.data ? created.data.id : undefined;
    if (core && typeof core.info === "function") {
      core.info(`Created sticky PR comment${createdId ? " " + createdId : ""} for marker ${marker}.`);
    }
    return { action: "created", comment_id: createdId };
  } catch (err) {
    const status = err && err.status;
    const message = err && err.message ? String(err.message) : "";
    if (status === 403 || message.includes("Resource not accessible by integration")) {
      if (core && typeof core.warning === "function") {
        core.warning(
          `Insufficient permissions to post or update sticky PR comment (status ${status || "unknown"}): ${message}. Skipping comment.`
        );
      }
      return { action: "forbidden-skipped" };
    }
    throw err;
  }
}

module.exports = postStickyComment;
module.exports.postStickyComment = postStickyComment;
