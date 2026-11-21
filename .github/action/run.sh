#!/usr/bin/env bash
set -euo pipefail

trim() {
  printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

to_lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

to_native_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

normalize_bool() {
  local name="$1"
  local raw="$2"
  local def="$3"
  local val
  val="$(to_lower "$(trim "$raw")")"
  if [ -z "$val" ]; then
    val="$def"
  fi
  case "$val" in
    true|false)
      printf '%s' "$val"
      ;;
    *)
      echo "Error: invalid boolean value '$raw' for '$name': expected 'true' or 'false'" >&2
      return 1
      ;;
  esac
}

MODE_RAW="${INPUT_MODE:-enforce}"
MODE="$(to_lower "$(trim "$MODE_RAW")")"
case "$MODE" in
  audit|warn|enforce)
    ;;
  *)
    echo "Error: invalid mode '$MODE_RAW': expected 'audit', 'warn', or 'enforce'" >&2
    exit 2
    ;;
esac

RUN_VERIFY="$(normalize_bool "run-verify" "${INPUT_RUN_VERIFY:-true}" "true")" || exit 2
REMEDIATE="$(normalize_bool "remediate" "${INPUT_REMEDIATE:-true}" "true")" || exit 2
COMMENT_PR="$(normalize_bool "comment-pr" "${INPUT_COMMENT_PR:-true}" "true")" || exit 2
UPLOAD_SARIF="$(normalize_bool "upload-sarif" "${INPUT_UPLOAD_SARIF:-false}" "false")" || exit 2

POLICY_ARGS=()
while IFS= read -r item; do
  if [ -n "$item" ]; then
    POLICY_ARGS+=("--policy" "$item")
  fi
done < <(printf '%s\n' "${INPUT_POLICY:-}" | tr -d '\r' | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

PACK_ARGS=()
while IFS= read -r item; do
  if [ -n "$item" ]; then
    PACK_ARGS+=("--pack" "$item")
  fi
done < <(printf '%s\n' "${INPUT_PACK:-}" | tr -d '\r' | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

PASS_FIXTURE_ARGS=()
while IFS= read -r item; do
  if [ -n "$item" ]; then
    PASS_FIXTURE_ARGS+=("--pass-fixtures" "$item")
  fi
done < <(printf '%s\n' "${INPUT_PASS_FIXTURES:-}" | tr -d '\r' | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

FAIL_FIXTURE_ARGS=()
while IFS= read -r item; do
  if [ -n "$item" ]; then
    FAIL_FIXTURE_ARGS+=("--fail-fixtures" "$item")
  fi
done < <(printf '%s\n' "${INPUT_FAIL_FIXTURES:-}" | tr -d '\r' | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

if [ "${#POLICY_ARGS[@]}" -eq 0 ] && [ "${#PACK_ARGS[@]}" -eq 0 ]; then
  echo "Error: either 'policy' or 'pack' input is required" >&2
  exit 2
fi

PLAN_INPUT="$(trim "${INPUT_PLAN:-}")"
SCHEMA_INPUT="$(trim "${INPUT_SCHEMA:-}")"
TF_DIR_INPUT="$(trim "${INPUT_TF_DIR:-.}")"
if [ -z "$TF_DIR_INPUT" ]; then
  TF_DIR_INPUT="."
fi
REPO_INPUT="$(trim "${INPUT_REPO_NAME:-}")"
if [ -z "$REPO_INPUT" ]; then
  REPO_INPUT="$(trim "${GITHUB_REPOSITORY:-}")"
fi

if [ "$RUN_VERIFY" = "false" ] && [ -z "$PLAN_INPUT" ]; then
  echo "Error: nothing to execute: 'run-verify' is false and 'plan' is empty" >&2
  exit 2
fi

if [ -n "$(trim "${TFSIM_BIN:-}")" ]; then
  TFSIM_CMD="$(trim "$TFSIM_BIN")"
  if [[ "$TFSIM_CMD" == */* ]] || [[ "$TFSIM_CMD" == *\\* ]]; then
    if [ -f "$TFSIM_CMD" ]; then
      TFSIM_CMD="$(cd "$(dirname "$TFSIM_CMD")" && pwd)/$(basename "$TFSIM_CMD")"
    fi
  fi
elif command -v tf-sim >/dev/null 2>&1; then
  TFSIM_CMD="$(command -v tf-sim)"
elif command -v tf-sim.exe >/dev/null 2>&1; then
  TFSIM_CMD="$(command -v tf-sim.exe)"
else
  echo "Error: tf-sim binary not found on PATH and TFSIM_BIN is unset" >&2
  exit 2
fi

WORK_DIR="$(trim "${INPUT_WORKING_DIRECTORY:-.}")"
if [ -z "$WORK_DIR" ]; then
  WORK_DIR="."
fi
if [ ! -d "$WORK_DIR" ]; then
  echo "Error: working-directory does not exist: $WORK_DIR" >&2
  exit 2
fi
cd "$WORK_DIR"

OUT_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tf-sim-run.XXXXXX")"

VERIFY_RC="skipped"
EVAL_RC="skipped"
VIOLATIONS_COUNT="0"
PATCHES_COUNT="0"
HAS_SARIF="false"
SARIF_FILE=""
MARKDOWN_FILE="$(to_native_path "$OUT_DIR/comment.md")"

COMMON_POLICY_ARGS=()
if [ "${#POLICY_ARGS[@]}" -gt 0 ]; then
  COMMON_POLICY_ARGS+=("${POLICY_ARGS[@]}")
fi
if [ "${#PACK_ARGS[@]}" -gt 0 ]; then
  COMMON_POLICY_ARGS+=("${PACK_ARGS[@]}")
fi

if [ "$RUN_VERIFY" = "true" ]; then
  VERIFY_ARGS=("${COMMON_POLICY_ARGS[@]}")
  if [ -n "$SCHEMA_INPUT" ]; then
    VERIFY_ARGS+=("--schema" "$SCHEMA_INPUT")
  fi
  if [ "${#PASS_FIXTURE_ARGS[@]}" -gt 0 ]; then
    VERIFY_ARGS+=("${PASS_FIXTURE_ARGS[@]}")
  fi
  if [ "${#FAIL_FIXTURE_ARGS[@]}" -gt 0 ]; then
    VERIFY_ARGS+=("${FAIL_FIXTURE_ARGS[@]}")
  fi

  set +e
  "$TFSIM_CMD" verify "${VERIFY_ARGS[@]}" --format json > "$OUT_DIR/verify.json" 2> "$OUT_DIR/verify.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    cat "$OUT_DIR/verify.err" >&2
    exit "$rc"
  fi
  VERIFY_RC="$rc"

  set +e
  "$TFSIM_CMD" verify "${VERIFY_ARGS[@]}" --format markdown > "$OUT_DIR/verify.md" 2> "$OUT_DIR/verify.md.err"
  rc_md=$?
  set -e
  if [ "$rc_md" -ne 0 ] && [ "$rc_md" -ne 1 ]; then
    cat "$OUT_DIR/verify.md.err" >&2
    exit "$rc_md"
  fi

  if [ -z "$PLAN_INPUT" ]; then
    set +e
    "$TFSIM_CMD" verify "${VERIFY_ARGS[@]}" --format sarif > "$OUT_DIR/tf-sim.sarif" 2> "$OUT_DIR/verify.sarif.err"
    rc_sarif=$?
    set -e
    if [ "$rc_sarif" -ne 0 ] && [ "$rc_sarif" -ne 1 ]; then
      cat "$OUT_DIR/verify.sarif.err" >&2
      exit "$rc_sarif"
    fi
    HAS_SARIF="true"
    SARIF_FILE="$(to_native_path "$OUT_DIR/tf-sim.sarif")"
  fi
fi

if [ -n "$PLAN_INPUT" ]; then
  EVAL_ARGS=("${COMMON_POLICY_ARGS[@]}" "--plan" "$PLAN_INPUT")
  if [ -n "$REPO_INPUT" ]; then
    EVAL_ARGS+=("--repo" "$REPO_INPUT")
  fi

  set +e
  "$TFSIM_CMD" eval "${EVAL_ARGS[@]}" --format json > "$OUT_DIR/eval.json" 2> "$OUT_DIR/eval.err"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    cat "$OUT_DIR/eval.err" >&2
    exit "$rc"
  fi
  EVAL_RC="$rc"

  VIOLATIONS_COUNT="$(node -e '
    const fs = require("fs");
    const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(String(Array.isArray(d.violations) ? d.violations.length : 0));
  ' "$(to_native_path "$OUT_DIR/eval.json")")"

  set +e
  "$TFSIM_CMD" eval "${EVAL_ARGS[@]}" --format markdown > "$OUT_DIR/eval.md" 2> "$OUT_DIR/eval.md.err"
  rc_md=$?
  set -e
  if [ "$rc_md" -ne 0 ] && [ "$rc_md" -ne 1 ]; then
    cat "$OUT_DIR/eval.md.err" >&2
    exit "$rc_md"
  fi

  set +e
  "$TFSIM_CMD" eval "${EVAL_ARGS[@]}" --format sarif > "$OUT_DIR/tf-sim.sarif" 2> "$OUT_DIR/eval.sarif.err"
  rc_sarif=$?
  set -e
  if [ "$rc_sarif" -ne 0 ] && [ "$rc_sarif" -ne 1 ]; then
    cat "$OUT_DIR/eval.sarif.err" >&2
    exit "$rc_sarif"
  fi
  HAS_SARIF="true"
  SARIF_FILE="$(to_native_path "$OUT_DIR/tf-sim.sarif")"

  if [ "$EVAL_RC" = "1" ] && [ "$REMEDIATE" = "true" ]; then
    REM_ARGS=("${COMMON_POLICY_ARGS[@]}" "--plan" "$PLAN_INPUT" "--tf-dir" "$TF_DIR_INPUT")
    if [ -n "$REPO_INPUT" ]; then
      REM_ARGS+=("--repo" "$REPO_INPUT")
    fi

    set +e
    "$TFSIM_CMD" remediate "${REM_ARGS[@]}" --format json > "$OUT_DIR/remediate.json" 2> "$OUT_DIR/remediate.err"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      cat "$OUT_DIR/remediate.err" >&2
      exit "$rc"
    fi

    PATCHES_COUNT="$(node -e '
      const fs = require("fs");
      const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(Array.isArray(d) ? d.length : 0));
    ' "$(to_native_path "$OUT_DIR/remediate.json")")"

    if [ "$PATCHES_COUNT" -gt 0 ]; then
      set +e
      "$TFSIM_CMD" remediate "${REM_ARGS[@]}" --format markdown > "$OUT_DIR/remediate.md" 2> "$OUT_DIR/remediate.md.err"
      rc_md=$?
      set -e
      if [ "$rc_md" -ne 0 ]; then
        cat "$OUT_DIR/remediate.md.err" >&2
        exit "$rc_md"
      fi
    fi
  fi
fi

HAS_VIOLATION="false"
if [ "$VERIFY_RC" = "1" ] || [ "$EVAL_RC" = "1" ]; then
  HAS_VIOLATION="true"
fi

if [ "$HAS_VIOLATION" = "false" ]; then
  FINAL_EXIT_CODE=0
elif [ "$MODE" = "audit" ]; then
  FINAL_EXIT_CODE=0
elif [ "$MODE" = "warn" ]; then
  FINAL_EXIT_CODE=0
  WARN_VERIFY_FILE=""
  WARN_EVAL_FILE=""
  if [ "$VERIFY_RC" = "1" ]; then
    WARN_VERIFY_FILE="$(to_native_path "$OUT_DIR/verify.json")"
  fi
  if [ "$EVAL_RC" = "1" ]; then
    WARN_EVAL_FILE="$(to_native_path "$OUT_DIR/eval.json")"
  fi
  node -e '
    const fs = require("fs");
    const escData = (s) => String(s || "").replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    const escProp = (s) => escData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

    const verifyFile = process.argv[1];
    const evalFile = process.argv[2];

    if (verifyFile && fs.existsSync(verifyFile)) {
      const v = JSON.parse(fs.readFileSync(verifyFile, "utf8"));
      for (const d of Array.isArray(v.diagnostics) ? v.diagnostics : []) {
        const props = [];
        if (d.policy_file) props.push("file=" + escProp(d.policy_file));
        if (d.line && Number(d.line) > 0) props.push("line=" + Number(d.line));
        const target = d.resource_type
          ? d.resource_type + (d.invalid_path ? "." + d.invalid_path : "") + ": "
          : "";
        const msg = `[${d.severity || "ERROR"}] ${target}${d.message || ""}`;
        const prefix = props.length > 0 ? `::warning ${props.join(",")}::` : "::warning::";
        process.stdout.write(prefix + escData(msg) + "\n");
      }
    }

    if (evalFile && fs.existsSync(evalFile)) {
      const e = JSON.parse(fs.readFileSync(evalFile, "utf8"));
      for (const vio of Array.isArray(e.violations) ? e.violations : []) {
        const msg = `[${vio.rule_id || "TFSIM"}][${vio.severity || "HIGH"}] ${vio.resource_address || ""}: ${vio.message || ""}`;
        process.stdout.write("::warning::" + escData(msg) + "\n");
      }
    }
  ' "$WARN_VERIFY_FILE" "$WARN_EVAL_FILE"
else
  FINAL_EXIT_CODE=1
fi

RAW_KEY="$(trim "${INPUT_COMMENT_KEY:-default}")"
SAFE_KEY="$(printf '%s' "$RAW_KEY" | tr '\r\n' '__' | sed 's/[^A-Za-z0-9._\/-]/_/g')"
if [ -z "$SAFE_KEY" ]; then
  SAFE_KEY="default"
fi
COMMENT_MARKER="<!-- tf-sim-sticky-comment:key=${SAFE_KEY} -->"

TFSIM_COMMENT_MARKER="$COMMENT_MARKER" \
TFSIM_MODE="$MODE" \
TFSIM_VERIFY_RC="$VERIFY_RC" \
TFSIM_EVAL_RC="$EVAL_RC" \
TFSIM_VIOLATIONS_COUNT="$VIOLATIONS_COUNT" \
TFSIM_PATCHES_COUNT="$PATCHES_COUNT" \
TFSIM_HAS_VIOLATION="$HAS_VIOLATION" \
TFSIM_VERIFY_MD="$([ -f "$OUT_DIR/verify.md" ] && to_native_path "$OUT_DIR/verify.md" || printf '')" \
TFSIM_EVAL_MD="$([ -f "$OUT_DIR/eval.md" ] && to_native_path "$OUT_DIR/eval.md" || printf '')" \
TFSIM_REMEDIATE_JSON="$([ -f "$OUT_DIR/remediate.json" ] && to_native_path "$OUT_DIR/remediate.json" || printf '')" \
TFSIM_REMEDIATE_MD="$([ -f "$OUT_DIR/remediate.md" ] && to_native_path "$OUT_DIR/remediate.md" || printf '')" \
TFSIM_OUT_MD="$MARKDOWN_FILE" \
TFSIM_OUT_SUMMARY_MD="$(to_native_path "$OUT_DIR/summary.md")" \
node -e '
  const fs = require("fs");

  const marker = process.env.TFSIM_COMMENT_MARKER;
  const mode = process.env.TFSIM_MODE;
  const verifyRC = process.env.TFSIM_VERIFY_RC;
  const evalRC = process.env.TFSIM_EVAL_RC;
  const violationsCount = Number(process.env.TFSIM_VIOLATIONS_COUNT || "0");
  const patchesCount = Number(process.env.TFSIM_PATCHES_COUNT || "0");
  const hasViolation = process.env.TFSIM_HAS_VIOLATION === "true";

  const verifyMdPath = process.env.TFSIM_VERIFY_MD;
  const evalMdPath = process.env.TFSIM_EVAL_MD;
  const remediateJsonPath = process.env.TFSIM_REMEDIATE_JSON;
  const remediateMdPath = process.env.TFSIM_REMEDIATE_MD;
  const outMdPath = process.env.TFSIM_OUT_MD;
  const outSummaryMdPath = process.env.TFSIM_OUT_SUMMARY_MD;

  function inlineCode(text) {
    const clean = String(text || "").replace(/[\r\n]+/g, " ");
    const matches = clean.match(/`+/g) || [];
    const maxTicks = matches.reduce((m, s) => Math.max(m, s.length), 0);
    const fence = "`".repeat(maxTicks + 1);
    const pad = clean.startsWith("`") || clean.endsWith("`") ? " " : "";
    return `${fence}${pad}${clean}${pad}${fence}`;
  }

  function safeTildeFence(text) {
    const matches = String(text || "").match(/~+/g) || [];
    const maxTildes = matches.reduce((m, s) => Math.max(m, s.length), 0);
    return "~".repeat(Math.max(4, maxTildes + 1));
  }

  let verdict = "✅ Passed";
  if (hasViolation) {
    if (mode === "audit") verdict = "⚠️ Violations Detected (Audit Mode)";
    else if (mode === "warn") verdict = "⚠️ Violations Detected (Warn Mode)";
    else verdict = "❌ Failed (Enforce Mode)";
  }

  let verifyStatus = "skipped";
  if (verifyRC === "0") verifyStatus = "✅ valid";
  else if (verifyRC === "1") verifyStatus = "❌ invalid";

  const parts = [];
  parts.push(marker);
  parts.push("");
  parts.push("## tf-sim Policy Report");
  parts.push("");
  parts.push("| Check | Result |");
  parts.push("| --- | --- |");
  parts.push(`| **Verdict** | ${verdict} |`);
  parts.push(`| **Mode** | \`${mode}\` |`);
  parts.push(`| **Policy Verification (\`verify\`)** | ${verifyStatus} |`);
  parts.push(`| **Plan Violations (\`eval\`)** | ${evalRC === "skipped" ? "skipped" : violationsCount} |`);
  parts.push(`| **HCL Patches (\`remediate\`)** | ${patchesCount} |`);

  if (verifyMdPath && fs.existsSync(verifyMdPath) && (verifyRC === "1" || evalRC === "skipped")) {
    const content = fs.readFileSync(verifyMdPath, "utf8").trim();
    if (content) {
      parts.push("");
      parts.push(content);
    }
  }

  if (evalRC !== "skipped" && evalMdPath && fs.existsSync(evalMdPath)) {
    const content = fs.readFileSync(evalMdPath, "utf8").trim();
    if (content) {
      parts.push("");
      parts.push(content);
    }
  }

  if (patchesCount > 0) {
    let remBody = "";
    if (remediateJsonPath && fs.existsSync(remediateJsonPath)) {
      const patches = JSON.parse(fs.readFileSync(remediateJsonPath, "utf8"));
      const hasJsonDiffs = Array.isArray(patches) && patches.some((p) => p && typeof p.unified_diff === "string" && p.unified_diff.length > 0);
      if (hasJsonDiffs) {
        const remParts = [`# Remediation Patches (${patches.length})`, ""];
        patches.forEach((p, idx) => {
          const diff = String(p.unified_diff || "");
          const fence = safeTildeFence(diff);
          remParts.push(`### Patch ${idx + 1}: ${inlineCode(p.resource_address || p.resource || "")}`);
          remParts.push("");
          remParts.push(`- **File:** ${inlineCode(p.file_path || p.file || "")}`);
          remParts.push("");
          remParts.push(`${fence}diff`);
          remParts.push(diff.endsWith("\n") ? diff.slice(0, -1) : diff);
          remParts.push(fence);
          remParts.push("");
        });
        remBody = remParts.join("\n").trim();
      }
    }
    if (!remBody && remediateMdPath && fs.existsSync(remediateMdPath)) {
      remBody = fs.readFileSync(remediateMdPath, "utf8").trim();
    }
    if (remBody) {
      parts.push("");
      parts.push("<details>");
      parts.push(`<summary>🔧 <b>Surgical HCL Auto-Remediation Diff (${patchesCount} patch(es))</b> — click to expand</summary>`);
      parts.push("");
      parts.push(remBody);
      parts.push("");
      parts.push("</details>");
    }
  }

  const MAX_LIMIT = 60000;
  const full = parts.join("\n") + "\n";
  fs.writeFileSync(outSummaryMdPath, full, "utf8");

  const notice = "\n\n> ⚠️ **Note:** Report truncated to fit GitHub PR comment size limits (60,000-byte cap). See the GitHub Actions job summary for complete details.\n";

  function updateState(line, state) {
    const m = line.match(/^\s*(`{3,}|~{3,})/);
    if (m) {
      const ch = m[1][0];
      const len = m[1].length;
      if (!state.fenceChar) {
        state.fenceChar = ch;
        state.fenceLen = len;
      } else if (state.fenceChar === ch && len >= state.fenceLen && /^\s*(`{3,}|~{3,})\s*$/.test(line)) {
        state.fenceChar = "";
        state.fenceLen = 0;
      }
    }
    if (!state.fenceChar) {
      const opens = (line.match(/<details(?:\s[^>]*)?>/gi) || []).length;
      const closes = (line.match(/<\/details>/gi) || []).length;
      state.detailsBalance += opens - closes;
    }
  }

  function closingSuffix(state) {
    let suffix = "";
    if (state.fenceChar) suffix += "\n" + state.fenceChar.repeat(state.fenceLen);
    if (state.detailsBalance > 0) suffix += "\n</details>".repeat(state.detailsBalance);
    return suffix + notice;
  }

  let commentOut = full;
  if (Buffer.byteLength(full, "utf8") > MAX_LIMIT || full.length > MAX_LIMIT) {
    const lines = full.split("\n");
    const state = { fenceChar: "", fenceLen: 0, detailsBalance: 0 };
    updateState(lines[0], state);
    const kept = [lines[0]];
    let curText = lines[0];
    let curBytes = Buffer.byteLength(curText, "utf8");
    let curChars = curText.length;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const nextState = { ...state };
      updateState(line, nextState);
      const suffix = closingSuffix(nextState);
      const addBytes = 1 + Buffer.byteLength(line, "utf8");
      const addChars = 1 + line.length;
      const suffixBytes = Buffer.byteLength(suffix, "utf8");
      if (curBytes + addBytes + suffixBytes > MAX_LIMIT || curChars + addChars + suffix.length > MAX_LIMIT) {
        break;
      }
      state.fenceChar = nextState.fenceChar;
      state.fenceLen = nextState.fenceLen;
      state.detailsBalance = nextState.detailsBalance;
      kept.push(line);
      curBytes += addBytes;
      curChars += addChars;
    }
    commentOut = kept.join("\n") + closingSuffix(state);
  }

  fs.writeFileSync(outMdPath, commentOut, "utf8");
'

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT_DIR/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'verify-exit-code=%s\n' "$VERIFY_RC"
    printf 'eval-exit-code=%s\n' "$EVAL_RC"
    printf 'exit-code=%s\n' "$FINAL_EXIT_CODE"
    printf 'violations-count=%s\n' "$VIOLATIONS_COUNT"
    printf 'patches-count=%s\n' "$PATCHES_COUNT"
    printf 'sarif-file=%s\n' "$SARIF_FILE"
    printf 'markdown-file=%s\n' "$MARKDOWN_FILE"
    printf 'comment-marker=%s\n' "$COMMENT_MARKER"
    printf 'has-comment=true\n'
    printf 'has-sarif=%s\n' "$HAS_SARIF"
  } >> "$GITHUB_OUTPUT"
fi

if [ "${TFSIM_DEFER_VIOLATION_EXIT:-false}" = "true" ]; then
  exit 0
fi

exit "$FINAL_EXIT_CODE"
