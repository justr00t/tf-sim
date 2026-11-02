(function () {
  'use strict';

  const root = document.documentElement;
  const stageTabs = document.querySelectorAll('[data-set-view]');
  const statePills = document.querySelectorAll('[data-set-state]');
  const filterBtns = document.querySelectorAll('[data-filter-provider]');

  let activePolicyFile = 'storage_encryption.rego';
  let activePolicyRelPath = 'testdata/policies/storage_encryption.rego';
  let activeCorpusDir = 'testdata/plans';
  let activeSchemaPath = 'testdata/schemas/multicloud_schema.json';
  let activeReposDir = 'testdata/repos';
  let activePatchKey = 'data-azure';
  let activeFilterProvider = 'all';
  let policySources = {};

  const fallbackPatches = {
    'payments-aws': {
      title: 'Unified Git Diff · testdata/repos/payments-aws/main.tf',
      addr: 'aws_s3_bucket.unencrypted_reports',
      attr: '["server_side_encryption_configuration", "rule", "apply_server_side_encryption_by_default", "sse_algorithm"] = "aws:kms"',
      rawPatch: '',
      lines: [
        ['21', '# Monthly financial reports bucket (currently missing server-side encryption)', ''],
        ['22', 'resource "aws_s3_bucket" "unencrypted_reports" {', ''],
        ['23', '  # Retain bucket name for downstream billing export', ''],
        ['24', '  bucket = "company-unencrypted-reports"', ''],
        ['+25', '+ server_side_encryption_configuration {', 'line-add'],
        ['+26', '+   rule {', 'line-add'],
        ['+27', '+     apply_server_side_encryption_by_default {', 'line-add'],
        ['+28', '+       sse_algorithm = "aws:kms"', 'line-add'],
        ['+29', '+     }', 'line-add'],
        ['+30', '+   }', 'line-add'],
        ['+31', '+ }', 'line-add'],
        ['32', '}', '']
      ]
    },
    'data-azure': {
      title: 'Unified Git Diff · testdata/repos/data-azure/main.tf',
      addr: 'azurerm_storage_account.insecure_transfer',
      attr: '["https_traffic_only_enabled"] = true',
      rawPatch: '',
      lines: [
        ['14', '# Legacy data ingestion storage account (non-compliant HTTPS setting)', ''],
        ['15', 'resource "azurerm_storage_account" "insecure_transfer" {', ''],
        ['16', '  name                     = "insecuretransfer"', ''],
        ['17', '  resource_group_name      = "rg-data"', ''],
        ['22', '  # Legacy toggle - must be remediated to true', ''],
        ['-23', '- https_traffic_only_enabled = false', 'line-del'],
        ['+23', '+ https_traffic_only_enabled = true', 'line-add'],
        ['24', '}', '']
      ]
    },
    'ml-gcp': {
      title: 'Unified Git Diff · testdata/repos/ml-gcp/main.tf',
      addr: 'google_storage_bucket.open_training_data',
      attr: '["uniform_bucket_level_access"] = true',
      rawPatch: '',
      lines: [
        ['14', '# Raw training dataset bucket (non-compliant ACL access setting)', ''],
        ['15', 'resource "google_storage_bucket" "open_training_data" {', ''],
        ['16', '  name     = "ml-training-raw"', ''],
        ['19', '  # Must enforce uniform bucket-level IAM access', ''],
        ['-20', '- uniform_bucket_level_access = false', 'line-del'],
        ['+20', '+ uniform_bucket_level_access = true', 'line-add'],
        ['21', '}', '']
      ]
    }
  };

  let livePatches = {
    'payments-aws': Object.assign({}, fallbackPatches['payments-aws']),
    'data-azure': Object.assign({}, fallbackPatches['data-azure']),
    'ml-gcp': Object.assign({}, fallbackPatches['ml-gcp'])
  };

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function updateCliPreview(viewName) {
    const cliEl = document.getElementById('cli-cmd-preview');
    if (!cliEl) return;
    const polPath = activePolicyRelPath || ('testdata/policies/' + activePolicyFile);
    const schemaPath = activeSchemaPath || 'testdata/schemas/multicloud_schema.json';
    const corpusDir = activeCorpusDir || 'testdata/plans/';
    const reposDir = activeReposDir || 'testdata/repos';
    const f = '-' + '-';
    if (viewName === 'verify') {
      cliEl.textContent = 'tf-sim verify ' + f + 'policy ' + polPath + ' ' + f + 'schema ' + schemaPath;
    } else if (viewName === 'remediate') {
      cliEl.textContent = 'tf-sim remediate ' + f + 'policy ' + polPath + ' ' + f + 'plan ' + corpusDir + ' ' + f + 'hcl-dir ' + reposDir + '/' + (activePatchKey || '');
    } else {
      cliEl.textContent = 'tf-sim backtest ' + f + 'policy ' + polPath + ' ' + f + 'corpus ' + corpusDir;
    }
  }

  function setView(viewName) {
    root.setAttribute('data-view', viewName);
    stageTabs.forEach(function (btn) {
      btn.setAttribute('aria-selected', btn.getAttribute('data-set-view') === viewName ? 'true' : 'false');
    });
    updateCliPreview(viewName);
  }

  function parseUnifiedDiffLines(unifiedDiff) {
    if (!unifiedDiff) return null;
    const rawLines = unifiedDiff.replace(/\r\n/g, '\n').split('\n');
    const parsed = [];
    let oldLn = 1;
    let newLn = 1;
    let inHunk = false;

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i];
      if (line.startsWith('\x2d\x2d\x2d ') || line.startsWith('+++ ')) {
        continue;
      }
      const hunkMatch = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (hunkMatch) {
        oldLn = parseInt(hunkMatch[1], 10);
        newLn = parseInt(hunkMatch[2], 10);
        inHunk = true;
        continue;
      }
      if (!inHunk) continue;
      if (line === '' && i === rawLines.length - 1) continue;

      if (line.startsWith('+')) {
        parsed.push(['+' + newLn, '+ ' + line.slice(1), 'line-add']);
        newLn++;
      } else if (line.startsWith('-')) {
        parsed.push(['-' + oldLn, '- ' + line.slice(1), 'line-del']);
        oldLn++;
      } else if (line.startsWith(' ')) {
        parsed.push([String(newLn), line.slice(1), '']);
        oldLn++;
        newLn++;
      }
    }
    return parsed.length > 0 ? parsed : null;
  }

  function bindPatchSelectButtons() {
    document.querySelectorAll('[data-select-patch]').forEach(function (btn) {
      btn.onclick = function () {
        renderPatch(btn.getAttribute('data-select-patch'));
      };
    });
  }

  function renderPatch(key) {
    const keys = Object.keys(livePatches);
    const titleEl = document.getElementById('patch-file-title');
    const addrEl = document.getElementById('rem-resource-addr');
    const attrEl = document.getElementById('rem-attr-path');
    const container = document.getElementById('hcl-diff-container');

    if (keys.length === 0) {
      activePatchKey = '';
      if (titleEl) titleEl.textContent = 'No HCL Patches Staged';
      if (addrEl) addrEl.innerHTML = '<code>None (0 violations or no matching .tf files)</code>';
      if (attrEl) attrEl.innerHTML = '<code>N/A</code>';
      if (container) {
        container.innerHTML = '<div class="code-line"><span class="code-ln">1</span><span class="code-src"># No surgical HCL patches are currently staged. Upload .tf files alongside violating plan.json files to generate hclwrite diffs.</span></div>';
      }
      updateCliPreview(root.getAttribute('data-view') || 'backtest');
      return;
    }

    activePatchKey = (key && key in livePatches) ? key : keys[0];
    document.querySelectorAll('[data-select-patch]').forEach(function (btn) {
      btn.setAttribute('aria-pressed', btn.getAttribute('data-select-patch') === activePatchKey ? 'true' : 'false');
    });
    const p = livePatches[activePatchKey];
    if (!p) return;

    if (titleEl) titleEl.textContent = p.title;
    if (addrEl) addrEl.innerHTML = '<code>' + escapeHtml(p.addr) + '</code>';
    if (attrEl) attrEl.innerHTML = '<code>' + escapeHtml(p.attr) + '</code>';
    if (container) {
      container.innerHTML = p.lines.map(function (l) {
        return '<div class="code-line ' + l[2] + '"><span class="code-ln">' + escapeHtml(l[0]) + '</span><span class="code-src">' + escapeHtml(l[1]) + '</span></div>';
      }).join('');
    }
    updateCliPreview(root.getAttribute('data-view') || 'backtest');
  }

  function renderPolicySourceLines(policyFile, sourceText, diagnostics) {
    const isBroken = (diagnostics && diagnostics.length > 0) || policyFile === 'broken_fail_open.rego';
    const banner = document.getElementById('verify-diag-banner');
    const badge = document.getElementById('rego-ast-badge');
    const title = document.getElementById('rego-pane-title');
    const code = document.getElementById('rego-code-container');
    const textarea = document.getElementById('rego-live-textarea');

    document.querySelectorAll('[data-select-policy]').forEach(function (btn) {
      btn.setAttribute('aria-pressed', btn.getAttribute('data-select-policy') === policyFile ? 'true' : 'false');
    });

    if (title) {
      title.textContent = activePolicyRelPath || ('testdata/policies/' + policyFile);
    }

    if (sourceText !== null && sourceText !== undefined && textarea && document.activeElement !== textarea) {
      textarea.value = sourceText;
    }

    if (diagnostics && diagnostics.length > 0) {
      const firstDiag = diagnostics[0];
      if (banner) {
        banner.hidden = false;
        banner.innerHTML =
          '<strong>[FAIL-OPEN SCHEMA ERROR]</strong> Line ' +
          escapeHtml(firstDiag.line || 14) +
          ' in <code>' +
          escapeHtml(policyFile) +
          '</code> references <code>rc.change.after.' +
          escapeHtml(firstDiag.attribute_path || 'https_only_enabled') +
          '</code> on <code>' +
          escapeHtml(firstDiag.resource_type || 'azurerm_storage_account') +
          '</code>. ' +
          escapeHtml(firstDiag.message || 'Attribute does not exist in provider schema.') +
          ' Standard OPA silently evaluates undefined paths as <code>PASS</code>.';
      }
      if (badge) {
        badge.className = 'badge-stamp stamp-blocked';
        badge.textContent = '[SCHEMA ERROR] ' + diagnostics.length + ' UNDEFINED ATTRIBUTE' + (diagnostics.length === 1 ? '' : 'S');
      }
    } else if (isBroken) {
      if (banner) banner.hidden = false;
      if (badge) {
        badge.className = 'badge-stamp stamp-blocked';
        badge.textContent = '[SCHEMA ERROR] 2 UNDEFINED ATTRIBUTES';
      }
    } else {
      if (banner) banner.hidden = true;
      if (badge) {
        badge.className = 'badge-stamp stamp-pass';
        badge.textContent = '[AST VALID] 0 SCHEMA TYPOS';
      }
    }

    if (sourceText && code) {
      const errLines = {};
      if (diagnostics) {
        diagnostics.forEach(function (d) {
          if (d.line) errLines[d.line] = true;
        });
      }
      const rawLines = sourceText.replace(/\r\n/g, '\n').split('\n');
      if (rawLines.length > 0 && rawLines[rawLines.length - 1] === '') {
        rawLines.pop();
      }
      code.innerHTML = rawLines.map(function (lineText, idx) {
        const ln = idx + 1;
        const cls = errLines[ln] ? 'line-error' : '';
        return '<div class="code-line ' + cls + '"><span class="code-ln">' + ln + '</span><span class="code-src">' + escapeHtml(lineText) + '</span></div>';
      }).join('');
      return;
    }

    if (!code) return;
    if (policyFile === 'No policy loaded') {
      code.innerHTML = '<div class="code-line"><span class="code-ln">1</span><span class="code-src"># No Rego policy loaded. Click "+ Load / Upload Files" in the top bar to upload a .rego policy.</span></div>';
      return;
    }
    if (isBroken) {
      code.innerHTML = [
        ['1', 'package tfsim', ''],
        ['3', 'import rego.v1', ''],
        ['9', '# Silent Fail-Open Bug 1: Typo in attribute name (https_only_enabled)', ''],
        ['10', 'deny contains violation if {', ''],
        ['11', '  some rc in input.resource_changes', ''],
        ['12', '  rc.type == "azurerm_storage_account"', 'line-error'],
        ['13', '  not is_delete(rc)', ''],
        ['14', '  rc.change.after.https_only_enabled == false  # <\x2d\x2d ERROR: attribute undefined in azurerm schema', 'line-error'],
        ['15', '  violation := {"rule_id": "AZURE-STORAGE-BROKEN-001", "severity": "HIGH"}', ''],
        ['23', '}', ''],
        ['28', '  rc.type == "aws_s3_bucket"', 'line-error'],
        ['30', '  rc.change.after.server_side_encryption_configuration[_].rule[_].invalid_encrypt == true', 'line-error']
      ].map(function (l) {
        return '<div class="code-line ' + l[2] + '"><span class="code-ln">' + l[0] + '</span><span class="code-src">' + escapeHtml(l[1]) + '</span></div>';
      }).join('');
    } else {
      code.innerHTML = [
        ['1', 'package tfsim', ''],
        ['3', 'import rego.v1', ''],
        ['42', '# Azure Storage Account: Require HTTPS traffic only enabled', ''],
        ['43', 'deny contains violation if {', ''],
        ['44', '  some rc in input.resource_changes', ''],
        ['45', '  rc.type == "azurerm_storage_account"', ''],
        ['47', '  rc.change.after.https_traffic_only_enabled == false', ''],
        ['48', '  violation := {"rule_id": "AZURE-STORAGE-HTTPS-001", "severity": "HIGH"}', ''],
        ['61', '}', '']
      ].map(function (l) {
        return '<div class="code-line ' + l[2] + '"><span class="code-ln">' + l[0] + '</span><span class="code-src">' + escapeHtml(l[1]) + '</span></div>';
      }).join('');
    }
  }

  function applyProviderFilter(prov) {
    activeFilterProvider = prov || 'all';
    filterBtns.forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-filter-provider') === activeFilterProvider ? 'true' : 'false');
    });
    document.querySelectorAll('#backtest-tbody tr[data-provider]').forEach(function (row) {
      row.style.display = (activeFilterProvider === 'all' || row.getAttribute('data-provider') === activeFilterProvider) ? '' : 'none';
    });
  }

  function setLoaderDrawerOpen(open) {
    const loaderDrawer = document.getElementById('workspace-loader-drawer');
    const openLoaderBtn = document.getElementById('btn-open-loader');
    if (!loaderDrawer) return;
    const isOpen = open === undefined ? loaderDrawer.hidden : Boolean(open);
    loaderDrawer.hidden = !isOpen;
    loaderDrawer.style.display = isOpen ? 'block' : 'none';
    if (openLoaderBtn) {
      openLoaderBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      openLoaderBtn.setAttribute('aria-pressed', isOpen ? 'true' : 'false');
    }
    if (isOpen && typeof loaderDrawer.scrollIntoView === 'function') {
      loaderDrawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  function bindDynamicTableActions() {
    document.querySelectorAll('#backtest-tbody [data-open-patch]').forEach(function (btn) {
      btn.onclick = function (ev) {
        ev.stopPropagation();
        renderPatch(btn.getAttribute('data-open-patch'));
        setView('remediate');
      };
    });
    document.querySelectorAll('#backtest-tbody [data-goto-view]').forEach(function (btn) {
      btn.onclick = function (ev) {
        ev.stopPropagation();
        setView(btn.getAttribute('data-goto-view'));
      };
    });
    document.querySelectorAll('#backtest-tbody tr[data-row-patch]').forEach(function (row) {
      row.onclick = function (ev) {
        if (ev.target && ev.target.closest('button')) return;
        const patchKey = row.getAttribute('data-row-patch');
        if (patchKey) {
          renderPatch(patchKey);
          setView('remediate');
        }
      };
      row.onkeydown = function (ev) {
        if (ev.key === 'Enter' || ev.key === ' ') {
          if (ev.target && ev.target.tagName === 'BUTTON') return;
          ev.preventDefault();
          const patchKey = row.getAttribute('data-row-patch');
          if (patchKey) {
            renderPatch(patchKey);
            setView('remediate');
          }
        }
      };
    });
    const emptyLoadBtn = document.getElementById('btn-empty-open-loader');
    if (emptyLoadBtn) {
      emptyLoadBtn.onclick = function () {
        setLoaderDrawerOpen(true);
      };
    }
    const emptyDemoBtn = document.getElementById('btn-empty-load-demo');
    if (emptyDemoBtn) {
      emptyDemoBtn.onclick = function () {
        syncFromServerState('violations-detected');
      };
    }
  }

  function renderSnapshotRowsTable(rows, stateName, isEmptyWorkspace) {
    const tbody = document.getElementById('backtest-tbody');
    if (!tbody) return;

    if (isEmptyWorkspace || !rows || rows.length === 0) {
      tbody.innerHTML =
        '<tr>' +
          '<td colspan="6" class="empty-ledger-cell">' +
            '<div><strong>0 Terraform Plan Snapshots Loaded</strong></div>' +
            '<div style="margin-top:0.35rem;">Pass your own <code>plan.json</code>, <code>.rego</code>, and <code>.tf</code> files using the browser uploader, or load the 3-cloud sample corpus.</div>' +
            '<div class="verdict-actions" style="justify-content:center; margin-top:0.85rem;">' +
              '<button type="button" class="tactile-btn cta-primary" id="btn-empty-open-loader" data-open-loader="open">+ Upload / Configure Files</button>' +
              '<button type="button" class="tactile-btn" id="btn-empty-load-demo">Load Sample 3-Cloud Corpus (testdata/)</button>' +
            '</div>' +
          '</td>' +
        '</tr>';
      bindDynamicTableActions();
      return;
    }

    tbody.innerHTML = rows.map(function (r) {
      const provShort = r.provider || 'aws';
      const provBadgeLabel = r.provider_full
        ? r.provider_full.replace('registry.terraform.io/', '')
        : ('hashicorp/' + provShort);
      const totalRes = r.total_resources || 0;
      const passRes = r.passed_resources !== undefined ? r.passed_resources : totalRes;
      const failRes = r.failed_resources !== undefined ? r.failed_resources : 0;
      const violations = r.violations || [];
      const firstV = violations.length > 0 ? violations[0] : null;
      const sev = firstV && firstV.severity ? firstV.severity.toUpperCase() : 'HIGH';

      let badgeCls = 'badge-stamp stamp-pass';
      let badgeTxt = '[PASS] 0 VIOLATIONS';
      let evalSub = passRes + ' pass · ' + failRes + ' fail';

      if (stateName === 'fail-open-caught') {
        if (provShort === 'google') {
          badgeCls = 'badge-stamp stamp-warn';
          badgeTxt = '[HALTED] UNVERIFIED';
          evalSub = 'Evaluation halted';
        } else {
          badgeCls = 'badge-stamp stamp-blocked';
          badgeTxt = '[FAIL-OPEN] SCHEMA ERR';
          evalSub = 'False pass blocked';
        }
      } else if (r.blocked || failRes > 0) {
        badgeCls = sev === 'MEDIUM' || sev === 'LOW' ? 'badge-stamp stamp-warn' : 'badge-stamp stamp-blocked';
        badgeTxt = '[BLOCKED] ' + failRes + ' ' + sev;
      }

      const ruleId = firstV ? firstV.rule_id : 'ALL-GUARDRAILS-PASS';
      const resAddr = firstV ? firstV.resource_address : 'All resources compliant';
      const patchKey = r.patch_key || r.repo_name;

      return (
        '<tr data-provider="' + escapeHtml(provShort) + '" data-row-patch="' + escapeHtml(patchKey) + '" tabindex="0" aria-label="Repository ' + escapeHtml(r.repo_name) + ' · Click to preview HCL remediation patch">' +
          '<td class="sticky-repo-col">' +
            '<div class="repo-name">' + escapeHtml(r.repo_name) + '</div>' +
            '<span class="repo-path">' + escapeHtml(r.source_path) + '</span>' +
          '</td>' +
          '<td><span class="code-inline">' + escapeHtml(provBadgeLabel) + '</span></td>' +
          '<td class="tabular">' +
            '<div>' + totalRes + ' resource' + (totalRes === 1 ? '' : 's') + '</div>' +
            '<div class="provider-sub">' + escapeHtml(evalSub) + '</div>' +
          '</td>' +
          '<td><span class="' + badgeCls + '">' + escapeHtml(badgeTxt) + '</span></td>' +
          '<td>' +
            '<div><span class="code-inline">' + escapeHtml(ruleId) + '</span></div>' +
            '<div class="violation-addr">' + escapeHtml(resAddr) + '</div>' +
          '</td>' +
          '<td>' +
            '<div class="row-actions">' +
              '<button type="button" class="tactile-btn" data-open-patch="' + escapeHtml(patchKey) + '">Preview HCL Patch &rarr;</button>' +
              '<button type="button" class="tactile-btn" data-goto-view="verify">Inspect Rule</button>' +
            '</div>' +
          '</td>' +
        '</tr>'
      );
    }).join('');

    bindDynamicTableActions();
    applyProviderFilter(activeFilterProvider);
  }

  function updateProviderFilterCountsAndStrip(rows, stateName, isEmptyWorkspace) {
    const counts = { all: 0, aws: 0, azurerm: 0, google: 0 };
    const violByProv = { aws: [], azurerm: [], google: [] };
    const resCountByProv = { aws: 0, azurerm: 0, google: 0 };

    if (!isEmptyWorkspace && Array.isArray(rows)) {
      counts.all = rows.length;
      rows.forEach(function (r) {
        const p = r.provider || 'aws';
        if (counts[p] !== undefined) counts[p]++;
        if (resCountByProv[p] !== undefined) resCountByProv[p] += (r.total_resources || 0);
        if (r.violations && r.violations.length > 0 && violByProv[p]) {
          r.violations.forEach(function (v) { violByProv[p].push(v); });
        }
      });
    }

    const labelMap = { all: 'All', aws: 'AWS', azurerm: 'Azure', google: 'GCP' };
    filterBtns.forEach(function (btn) {
      const k = btn.getAttribute('data-filter-provider');
      if (k && labelMap[k]) {
        btn.textContent = labelMap[k] + ' (' + (counts[k] || 0) + ')';
      }
    });

    const provAwsBadge = document.getElementById('prov-aws-badge');
    const provAzureBadge = document.getElementById('prov-azure-badge');
    const provGcpBadge = document.getElementById('prov-gcp-badge');

    function applyCardBadge(badgeEl, provKey, defaultLineErr) {
      if (!badgeEl) return;
      if (isEmptyWorkspace || counts.all === 0) {
        badgeEl.className = 'badge-stamp';
        badgeEl.textContent = '0 LOADED';
        return;
      }
      if (stateName === 'fail-open-caught') {
        if (provKey === 'google') {
          badgeEl.className = 'badge-stamp stamp-warn';
          badgeEl.textContent = 'UNVERIFIED';
        } else {
          badgeEl.className = 'badge-stamp stamp-blocked';
          badgeEl.textContent = 'SCHEMA ERROR (' + defaultLineErr + ')';
        }
        return;
      }
      const vList = violByProv[provKey] || [];
      if (vList.length === 0) {
        badgeEl.className = 'badge-stamp stamp-pass';
        badgeEl.textContent = resCountByProv[provKey] > 0 ? '0 VIOLATIONS (PASS)' : '0 RESOURCES';
      } else {
        const sev = (vList[0].severity || 'HIGH').toUpperCase();
        badgeEl.className = (sev === 'MEDIUM' || sev === 'LOW') ? 'badge-stamp stamp-warn' : 'badge-stamp stamp-blocked';
        badgeEl.textContent = vList.length + ' VIOLATION' + (vList.length === 1 ? '' : 'S') + ' (' + sev + ')';
      }
    }

    applyCardBadge(provAwsBadge, 'aws', 'LINE 30');
    applyCardBadge(provAzureBadge, 'azurerm', 'LINE 14');
    applyCardBadge(provGcpBadge, 'google', '');
  }

  function renderFullWorkspaceFromAPI(ws) {
    if (!ws) return;
    const isEmpty = Boolean(ws.empty_workspace) || ws.state === 'empty';
    const stateName = isEmpty ? 'empty' : (ws.state || 'violations-detected');

    root.setAttribute('data-state', stateName);
    statePills.forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-set-state') === stateName ? 'true' : 'false');
    });

    if (ws.active_policy) activePolicyRelPath = ws.active_policy;
    if (ws.active_policy_name) activePolicyFile = ws.active_policy_name;
    if (ws.corpus_dir !== undefined) activeCorpusDir = ws.corpus_dir;
    if (ws.schema_path !== undefined) activeSchemaPath = ws.schema_path;
    if (ws.repos_dir !== undefined) activeReposDir = ws.repos_dir;

    if (ws.raw_policy_source && activePolicyFile) {
      policySources[activePolicyFile] = ws.raw_policy_source;
    }

    const bt = ws.backtest || {};
    const totalRepos = bt.total_repos_analyzed || 0;
    const blockedRepos = bt.blocked_plans_count || 0;
    const totalRes = bt.total_resources || 0;
    const totalViolations = bt.total_violations || 0;
    const diags = (ws.verification && ws.verification.diagnostics) ? ws.verification.diagnostics : [];
    const patches = Array.isArray(ws.patches) ? ws.patches : [];
    const rows = Array.isArray(ws.snapshot_rows) ? ws.snapshot_rows : [];

    // Update top bar pills
    const corpusPill = document.getElementById('corpus-pill');
    const schemaPill = document.getElementById('schema-pill');
    const polPill = document.getElementById('active-policy-pill');
    const evalEl = document.getElementById('verdict-eval-time');

    if (corpusPill) {
      if (isEmpty) {
        corpusPill.textContent = 'No plans loaded (0 repos · 0 resources)';
      } else {
        const prefix = ws.custom_uploaded ? 'uploaded/' + (ws.corpus_dir || 'plans') : (ws.corpus_dir || 'testdata/plans');
        corpusPill.textContent = prefix + ' (' + totalRepos + ' repo' + (totalRepos === 1 ? '' : 's') + ' · ' + totalRes + ' resource' + (totalRes === 1 ? '' : 's') + ')';
      }
    }
    if (schemaPill) {
      schemaPill.textContent = isEmpty ? 'None loaded' : (ws.schema_path || 'multicloud_schema.json');
    }
    if (polPill) {
      polPill.textContent = isEmpty ? 'No policy loaded' : (ws.active_policy_name || 'storage_encryption.rego');
    }
    if (evalEl && ws.eval_duration_ms !== undefined) {
      evalEl.textContent = 'Eval: ' + ws.eval_duration_ms + 'ms · ' + (ws.workers || 8) + ' Workers';
    }

    // Update Verdict Banner & Telemetry
    const stamp = document.getElementById('verdict-stamp');
    const astPill = document.getElementById('verdict-ast-pill');
    const title = document.getElementById('verdict-title');
    const desc = document.getElementById('verdict-desc');

    if (isEmpty) {
      if (stamp) {
        stamp.className = 'badge-stamp stamp-warn';
        stamp.textContent = '[IDLE] NO CORPUS LOADED';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: IDLE (0 Loaded)';
      if (title) {
        title.innerHTML = 'Workspace Ready: <em>0 of 0 repositories</em> loaded · Click <button type="button" class="state-pill" data-open-loader="open">+ Load / Upload Files</button> to evaluate plans';
      }
      if (desc) {
        desc.textContent = 'No Terraform plan snapshots or Rego policies are currently loaded. Upload your own plan.json and .rego files from the browser, configure local workspace paths, or load the 3-cloud sample corpus.';
      }
      document.getElementById('metric-repos').textContent = '0 / 0';
      document.getElementById('metric-repos-sub').textContent = '0.0% corpus blast radius';
      document.getElementById('metric-violations').textContent = '0';
      document.getElementById('metric-violations-sub').textContent = '0 resources evaluated';
      document.getElementById('metric-schema').textContent = '0 Errors';
      document.getElementById('metric-schema-sub').textContent = '0 resource types verified';
      document.getElementById('metric-patches').textContent = '0 .patch';
      document.getElementById('metric-patches-sub').textContent = 'Upload .tf files for auto-fix';
    } else if (stateName === 'fail-open-caught') {
      const firstLine = (diags[0] && diags[0].line) ? diags[0].line : 14;
      const firstAttr = (diags[0] && diags[0].attribute_path) ? diags[0].attribute_path : 'https_only_enabled';
      if (stamp) {
        stamp.className = 'badge-stamp stamp-blocked';
        stamp.textContent = '[FAIL-OPEN CAUGHT] SCHEMA TYPO AT LINE ' + firstLine;
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: INVALID (' + diags.length + ' Error' + (diags.length === 1 ? '' : 's') + ')';
      if (title) {
        title.innerHTML = 'Silent Fail-Open Blocked: <em>' + escapeHtml(activePolicyFile) + '</em> queries non-existent attribute <code>' + escapeHtml(firstAttr) + '</code>';
      }
      if (desc) {
        desc.textContent = 'Standard OPA evaluation returned 0 violations (false pass) because undefined schema paths evaluate to false. tf-sim verify halted promotion.';
      }
      document.getElementById('metric-repos').textContent = '0 / ' + totalRepos;
      document.getElementById('metric-repos-sub').textContent = 'False-pass prevented by AST check';
      document.getElementById('metric-violations').textContent = '0 (False)';
      document.getElementById('metric-schema').textContent = diags.length + ' Error' + (diags.length === 1 ? '' : 's');
      document.getElementById('metric-schema-sub').textContent = 'Undefined provider schema path';
      document.getElementById('metric-patches').textContent = patches.length + ' .patch';
    } else if (stateName === 'enforce-ready') {
      if (stamp) {
        stamp.className = 'badge-stamp stamp-pass';
        stamp.textContent = '[SAFE TO ENFORCE] ZERO BLAST RADIUS';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: VALID (0 Typos)';
      if (title) {
        title.innerHTML = 'Enforce Readiness: <em>0 of ' + totalRepos + ' repositories</em> blocked; safe to promote <span>' + escapeHtml(activePolicyFile) + '</span> to CI/CD deny';
      }
      if (desc) {
        desc.textContent = 'Evaluation across ' + totalRepos + ' repository plan' + (totalRepos === 1 ? '' : 's') + ' (' + totalRes + ' resources) confirmed 0 policy violations.';
      }
      document.getElementById('metric-repos').textContent = '0 / ' + totalRepos;
      document.getElementById('metric-repos-sub').textContent = '100.0% corpus compliant';
      document.getElementById('metric-violations').textContent = '0';
      document.getElementById('metric-schema').textContent = '0 Errors';
      document.getElementById('metric-patches').textContent = '0 Pending';
    } else {
      const pct = totalRepos > 0 ? ((blockedRepos / totalRepos) * 100).toFixed(1) : '0.0';
      if (stamp) {
        stamp.className = 'badge-stamp stamp-blocked';
        stamp.textContent = '[BLOCKED] DO NOT FLIP TO DENY';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: VALID (0 Typos)';
      if (title) {
        title.innerHTML = 'Enforce Readiness: <em>' + blockedRepos + ' of ' + totalRepos + ' repositories</em> would fail CI/CD under <span>' + escapeHtml(activePolicyFile) + '</span>';
      }
      if (desc) {
        desc.textContent = 'Historical backtest across ' + totalRepos + ' repository plan' + (totalRepos === 1 ? '' : 's') + ' surfaced ' + totalViolations + ' non-compliant resource' + (totalViolations === 1 ? '' : 's') + '.';
      }
      document.getElementById('metric-repos').textContent = blockedRepos + ' / ' + totalRepos;
      document.getElementById('metric-repos-sub').textContent = pct + '% corpus blast radius';
      document.getElementById('metric-violations').textContent = String(totalViolations);
      document.getElementById('metric-schema').textContent = '0 Errors';
      document.getElementById('metric-patches').textContent = patches.length + ' .patch';
    }

    // Update Stage A Table & Provider Strip
    updateProviderFilterCountsAndStrip(rows, stateName, isEmpty);
    renderSnapshotRowsTable(rows, stateName, isEmpty);

    // Update Stage B Policy Source
    renderPolicySourceLines(
      isEmpty ? 'No policy loaded' : activePolicyFile,
      isEmpty ? '' : (ws.raw_policy_source || policySources[activePolicyFile] || null),
      diags
    );

    // Update Stage C Patches
    livePatches = {};
    patches.forEach(function (p) {
      const key = p.key || p.repo_name || 'patch';
      const fp = (p.file_path || '').replace(/\\/g, '/');
      let attrStr = 'remediation attribute';
      if (p.remediation && Array.isArray(p.remediation.attribute_path)) {
        attrStr = JSON.stringify(p.remediation.attribute_path) + ' = ' + JSON.stringify(p.remediation.suggested_value);
      }
      const diffLines = parseUnifiedDiffLines(p.unified_diff) || [
        ['1', p.patched_hcl || '# Patched HCL', 'line-add']
      ];
      livePatches[key] = {
        title: 'Unified Git Diff · ' + fp,
        addr: p.resource_address || '',
        attr: attrStr,
        rawPatch: p.unified_diff || '',
        lines: diffLines
      };
    });

    // Rebuild Stage C patch selector buttons if custom patches exist
    const patchSelectorGroup = document.querySelector('[aria-label="Select Repository Patch"]');
    if (patchSelectorGroup) {
      const patchKeys = Object.keys(livePatches);
      if (patchKeys.length > 0) {
        patchSelectorGroup.innerHTML =
          '<span class="filter-label">Repository Target:</span>' +
          patchKeys.map(function (k, idx) {
            const p = livePatches[k];
            return '<button type="button" class="filter-btn" data-select-patch="' + escapeHtml(k) + '" aria-pressed="' + (idx === 0 ? 'true' : 'false') + '">' + escapeHtml(k) + ' (' + escapeHtml(p.addr || 'main.tf') + ')</button>';
          }).join('');
        bindPatchSelectButtons();
      } else {
        patchSelectorGroup.innerHTML = '<span class="filter-label">Repository Target: None Staged</span>';
      }
    }

    renderPatch(activePatchKey);
    updateCliPreview(root.getAttribute('data-view') || 'backtest');
  }

  function applyDomState(stateName, telemetryOverride) {
    root.setAttribute('data-state', stateName);
    statePills.forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-set-state') === stateName ? 'true' : 'false');
    });

    if (stateName === 'empty') {
      renderFullWorkspaceFromAPI({
        state: 'empty',
        empty_workspace: true,
        active_policy_name: 'No policy loaded',
        backtest: { total_repos_analyzed: 0, blocked_plans_count: 0, total_resources: 0, total_violations: 0 },
        snapshot_rows: [],
        patches: []
      });
      return;
    }

    const stamp = document.getElementById('verdict-stamp');
    const astPill = document.getElementById('verdict-ast-pill');
    const title = document.getElementById('verdict-title');
    const desc = document.getElementById('verdict-desc');
    const polPill = document.getElementById('active-policy-pill');

    if (stateName === 'fail-open-caught') {
      activePolicyFile = 'broken_fail_open.rego';
      const diagCount = (telemetryOverride && telemetryOverride.diagCount) || 2;
      if (stamp) {
        stamp.className = 'badge-stamp stamp-blocked';
        stamp.textContent = '[FAIL-OPEN CAUGHT] SCHEMA TYPO AT LINE 12';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: INVALID (' + diagCount + ' Errors)';
      if (polPill) polPill.textContent = 'broken_fail_open.rego';
      if (title) title.innerHTML = 'Silent Fail-Open Blocked: <em>broken_fail_open.rego</em> queries non-existent attribute <code>https_only_enabled</code>';
      if (desc) desc.textContent = 'Standard OPA evaluation returned 0 violations (100% false pass) because undefined schema paths evaluate to false. tf-sim verify halted promotion.';
      document.getElementById('metric-repos').textContent = '0 / 3';
      document.getElementById('metric-repos-sub').textContent = 'False-pass prevented by AST check';
      document.getElementById('metric-violations').textContent = '0 (False)';
      document.getElementById('metric-schema').textContent = diagCount + ' Errors';
      document.getElementById('metric-schema-sub').textContent = 'Line 14 & Line 30 invalid paths';
      renderPolicySourceLines(
        'broken_fail_open.rego',
        policySources['broken_fail_open.rego'] || null,
        telemetryOverride && telemetryOverride.diagnostics
      );
    } else if (stateName === 'enforce-ready') {
      activePolicyFile = 'storage_encryption.rego';
      if (stamp) {
        stamp.className = 'badge-stamp stamp-pass';
        stamp.textContent = '[SAFE TO ENFORCE] ZERO BLAST RADIUS';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: VALID (0 Typos)';
      if (polPill) polPill.textContent = 'storage_encryption.rego';
      if (title) title.innerHTML = 'Enforce Readiness: <em>0 of 3 repositories</em> blocked; safe to promote policy to CI/CD deny';
      if (desc) desc.textContent = 'All 3 surgical hclwrite patches applied across AWS, Azure, and GCP repositories. Re-simulation confirms 6 of 6 storage resources satisfy encryption guardrails.';
      document.getElementById('metric-repos').textContent = '0 / 3';
      document.getElementById('metric-repos-sub').textContent = '100.0% corpus compliant';
      document.getElementById('metric-violations').textContent = '0';
      document.getElementById('metric-schema').textContent = '0 Errors';
      document.getElementById('metric-patches').textContent = '0 Pending';
      renderPolicySourceLines('storage_encryption.rego', policySources['storage_encryption.rego'] || null, []);
    } else {
      activePolicyFile = 'storage_encryption.rego';
      const totalRepos = (telemetryOverride && telemetryOverride.totalRepos) || 3;
      const blockedRepos = (telemetryOverride && telemetryOverride.blockedRepos !== undefined) ? telemetryOverride.blockedRepos : 3;
      const totalViolations = (telemetryOverride && telemetryOverride.totalViolations !== undefined) ? telemetryOverride.totalViolations : 3;
      if (stamp) {
        stamp.className = 'badge-stamp stamp-blocked';
        stamp.textContent = '[BLOCKED] DO NOT FLIP TO DENY';
      }
      if (astPill) astPill.textContent = 'AST & Schema Check: VALID (0 Typos)';
      if (polPill) polPill.textContent = 'storage_encryption.rego';
      if (title) title.innerHTML = 'Enforce Readiness: <em>' + blockedRepos + ' of ' + totalRepos + ' repositories</em> would fail CI/CD under <span>storage_encryption.rego</span>';
      if (desc) desc.textContent = 'Historical backtest across 3 cloud providers surfaced ' + totalViolations + ' non-compliant storage resources. Surgical hclwrite remediation patches are staged and verified to preserve existing HCL comments.';
      document.getElementById('metric-repos').textContent = blockedRepos + ' / ' + totalRepos;
      document.getElementById('metric-repos-sub').textContent = '100.0% corpus blast radius';
      document.getElementById('metric-violations').textContent = String(totalViolations);
      document.getElementById('metric-schema').textContent = '0 Errors';
      document.getElementById('metric-patches').textContent = '3 .patch';
      renderPolicySourceLines('storage_encryption.rego', policySources['storage_encryption.rego'] || null, []);
    }
    updateCliPreview(root.getAttribute('data-view') || 'backtest');
  }

  async function syncFromServerState(stateName) {
    try {
      const res = await fetch('/api/workspace?state=' + encodeURIComponent(stateName));
      if (res.ok) {
        const ws = await res.json();
        renderFullWorkspaceFromAPI(ws);
        return;
      }
    } catch (_err) {
      // Offline or standalone HTML mode: fall back to deterministic in-memory state.
    }
    applyDomState(stateName);
  }

  async function loadInitialWorkspace() {
    try {
      const wsRes = await fetch('/api/workspace');
      if (wsRes.ok) {
        const ws = await wsRes.json();
        renderFullWorkspaceFromAPI(ws);
        return;
      }
    } catch (_err) {
      // Offline fallback
    }
    renderPatch(activePatchKey);
    applyDomState(root.getAttribute('data-state') || 'violations-detected');
  }

  // Stage navigation tabs
  stageTabs.forEach(function (btn) {
    btn.addEventListener('click', function () {
      setView(btn.getAttribute('data-set-view'));
    });
  });

  // State switcher pills
  statePills.forEach(function (btn) {
    btn.addEventListener('click', function () {
      const targetState = btn.getAttribute('data-set-state');
      syncFromServerState(targetState);
    });
  });

  // Goto view buttons
  document.querySelectorAll('[data-goto-view]').forEach(function (btn) {
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      setView(btn.getAttribute('data-goto-view'));
    });
  });

  bindDynamicTableActions();
  bindPatchSelectButtons();

  // Select policy buttons in Stage B
  document.querySelectorAll('[data-select-policy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const pol = btn.getAttribute('data-select-policy');
      activePolicyFile = pol;
      if (pol === 'broken_fail_open.rego') {
        syncFromServerState('fail-open-caught');
      } else {
        syncFromServerState('violations-detected');
      }
    });
  });

  // Provider filter buttons in Stage A
  filterBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      applyProviderFilter(btn.getAttribute('data-filter-provider'));
    });
  });

  // Workspace File Loader & Upload Drawer controls
  const closeLoaderBtn = document.getElementById('btn-close-loader');
  if (closeLoaderBtn) {
    closeLoaderBtn.addEventListener('click', function () {
      setLoaderDrawerOpen(false);
    });
  }

  document.addEventListener('click', function (ev) {
    const trigger = ev.target && ev.target.closest ? ev.target.closest('[data-open-loader]') : null;
    if (!trigger) return;
    ev.preventDefault();
    const mode = trigger.getAttribute('data-open-loader');
    if (mode === 'open') {
      setLoaderDrawerOpen(true);
    } else if (mode === 'close') {
      setLoaderDrawerOpen(false);
    } else {
      setLoaderDrawerOpen();
    }
  });

  function readFileAsText(file) {
    return new Promise(function (resolve, reject) {
      const reader = new FileReader();
      reader.onload = function () {
        resolve({ name: file.name, content: String(reader.result || '') });
      };
      reader.onerror = function () {
        reject(new Error('Failed to read file ' + file.name));
      };
      reader.readAsText(file);
    });
  }

  const submitUploadBtn = document.getElementById('btn-submit-upload');
  if (submitUploadBtn) {
    submitUploadBtn.addEventListener('click', async function () {
      const statusEl = document.getElementById('upload-status-msg');
      const planInput = document.getElementById('upload-plan-files');
      const policyInput = document.getElementById('upload-policy-file');
      const schemaInput = document.getElementById('upload-schema-file');
      const builtinSchemaChk = document.getElementById('upload-use-builtin-schema');
      const tfInput = document.getElementById('upload-tf-files');

      try {
        if (statusEl) statusEl.textContent = 'Reading selected files...';
        const planFiles = [];
        if (planInput && planInput.files) {
          for (let i = 0; i < planInput.files.length; i++) {
            planFiles.push(await readFileAsText(planInput.files[i]));
          }
        }
        let policyFile = null;
        if (policyInput && policyInput.files && policyInput.files.length > 0) {
          policyFile = await readFileAsText(policyInput.files[0]);
        }
        let schemaFile = null;
        if (schemaInput && schemaInput.files && schemaInput.files.length > 0) {
          schemaFile = await readFileAsText(schemaInput.files[0]);
        }
        const tfFiles = [];
        if (tfInput && tfInput.files) {
          for (let i = 0; i < tfInput.files.length; i++) {
            tfFiles.push(await readFileAsText(tfInput.files[i]));
          }
        }

        if (planFiles.length === 0 && !policyFile) {
          if (statusEl) statusEl.textContent = 'Select at least one plan.json file or .rego policy file first.';
          return;
        }

        if (statusEl) statusEl.textContent = 'Uploading & evaluating in local sandbox...';
        const res = await fetch('/api/workspace/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            plan_files: planFiles,
            policy_file: policyFile,
            schema_file: schemaFile,
            use_builtin_schema: builtinSchemaChk ? builtinSchemaChk.checked : true,
            tf_files: tfFiles
          })
        });
        const data = await res.json();
        if (!res.ok) {
          if (statusEl) statusEl.textContent = 'Error: ' + (data.error || 'Upload failed');
          return;
        }
        if (statusEl) {
          statusEl.textContent = 'Loaded ' + planFiles.length + ' plan(s) into local sandbox.';
        }
        renderFullWorkspaceFromAPI(data);
        setLoaderDrawerOpen(false);
      } catch (err) {
        if (statusEl) statusEl.textContent = 'Upload failed: ' + (err && err.message ? err.message : 'network error');
      }
    });
  }

  const applyPathsBtn = document.getElementById('btn-apply-paths');
  if (applyPathsBtn) {
    applyPathsBtn.addEventListener('click', async function () {
      const corpusVal = (document.getElementById('cfg-corpus-dir') || {}).value || '';
      const policyVal = (document.getElementById('cfg-policy-path') || {}).value || '';
      const schemaVal = (document.getElementById('cfg-schema-path') || {}).value || '';
      const reposVal = (document.getElementById('cfg-repos-dir') || {}).value || '';
      try {
        const res = await fetch('/api/workspace/configure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mode: 'paths',
            corpus_dir: corpusVal,
            policy_path: policyVal,
            schema_path: schemaVal,
            repos_dir: reposVal
          })
        });
        if (res.ok) {
          const ws = await res.json();
          renderFullWorkspaceFromAPI(ws);
          setLoaderDrawerOpen(false);
        }
      } catch (_err) {
        // Ignore offline error
      }
    });
  }

  const loadDemoBtn = document.getElementById('btn-load-demo-corpus');
  if (loadDemoBtn) {
    loadDemoBtn.addEventListener('click', async function () {
      await syncFromServerState('violations-detected');
      setLoaderDrawerOpen(false);
    });
  }

  const clearWorkspaceBtn = document.getElementById('btn-clear-workspace');
  if (clearWorkspaceBtn) {
    clearWorkspaceBtn.addEventListener('click', async function () {
      await syncFromServerState('empty');
      setLoaderDrawerOpen(false);
    });
  }

  // Stage B Live Rego Editor toggle & live verify
  const toggleEditorBtn = document.getElementById('btn-toggle-editor');
  const editorWrap = document.getElementById('rego-editor-wrap');
  const verifyLiveBtn = document.getElementById('btn-verify-live');
  const resetEditorBtn = document.getElementById('btn-reset-editor');
  const liveTextarea = document.getElementById('rego-live-textarea');

  if (toggleEditorBtn && editorWrap) {
    toggleEditorBtn.addEventListener('click', function () {
      const nextHidden = !editorWrap.hidden;
      editorWrap.hidden = nextHidden;
      toggleEditorBtn.setAttribute('aria-pressed', nextHidden ? 'false' : 'true');
      if (!nextHidden && liveTextarea && !liveTextarea.value) {
        liveTextarea.value = policySources[activePolicyFile] || '';
      }
    });
  }

  if (verifyLiveBtn && liveTextarea) {
    verifyLiveBtn.addEventListener('click', async function () {
      const content = liveTextarea.value;
      try {
        const res = await fetch('/api/backtest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            policy_path: activePolicyRelPath || ('testdata/policies/' + activePolicyFile),
            policy_content: content
          })
        });
        if (res.ok) {
          const data = await res.json();
          const diags = data.diagnostics || [];
          renderPolicySourceLines(activePolicyFile, content, diags);
          if (diags.length > 0) {
            applyDomState('fail-open-caught', { diagCount: diags.length, diagnostics: diags });
          } else if (data.blocked_plans_count === 0) {
            applyDomState('enforce-ready');
          } else {
            applyDomState('violations-detected', {
              totalRepos: data.total_repos_analyzed || 3,
              blockedRepos: data.blocked_plans_count,
              totalViolations: data.total_violations
            });
            try {
              await fetch('/api/remediate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  policy_path: activePolicyRelPath || ('testdata/policies/' + activePolicyFile),
                  policy_content: content
                })
              });
            } catch (_remErr) {
              // Ignore optional remediate refresh failure
            }
          }
        }
      } catch (_err) {
        renderPolicySourceLines(activePolicyFile, content, []);
      }
    });
  }

  if (resetEditorBtn && liveTextarea) {
    resetEditorBtn.addEventListener('click', function () {
      const orig = policySources[activePolicyFile] || '';
      liveTextarea.value = orig;
      syncFromServerState(activePolicyFile === 'broken_fail_open.rego' ? 'fail-open-caught' : 'violations-detected');
    });
  }

  // Stage C Apply Patch button
  const applyPatchBtn = document.getElementById('btn-apply-patch');
  if (applyPatchBtn) {
    applyPatchBtn.addEventListener('click', async function () {
      try {
        const res = await fetch('/api/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo: 'all' })
        });
        if (res.ok) {
          const wsRes = await fetch('/api/workspace');
          if (wsRes.ok) {
            const ws = await wsRes.json();
            renderFullWorkspaceFromAPI(ws);
            setView('backtest');
            return;
          }
        }
      } catch (_err) {
        // Fallback
      }
      await syncFromServerState('enforce-ready');
      setView('backtest');
    });
  }

  // Stage C Export .patch File button
  const exportPatchBtn = document.getElementById('btn-export-patch');
  if (exportPatchBtn) {
    exportPatchBtn.addEventListener('click', function () {
      const p = livePatches[activePatchKey] || fallbackPatches['data-azure'];
      const patchText = p.rawPatch || p.lines.map(function (l) { return l[1]; }).join('\n') + '\n';
      const blob = new Blob([patchText], { type: 'text/x-diff;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = (activePatchKey || 'terraform') + '-remediation.patch';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // Verdict CTA Run Full Corpus Simulation button
  const runSimBtn = document.getElementById('btn-run-sim');
  if (runSimBtn) {
    runSimBtn.addEventListener('click', function () {
      const cur = root.getAttribute('data-state') || 'violations-detected';
      syncFromServerState(cur === 'empty' ? 'violations-detected' : cur);
    });
  }

  loadInitialWorkspace();
})();
