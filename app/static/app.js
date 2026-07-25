"use strict";

let csrfToken = "";
let bootstrapState = null;
let privateKeyText = "";
let pcPrivateKeyText = "";
let apiCaText = "";
let inspectedFingerprint = null;
let fingerprintInspectionSequence = 0;
let currentJob = null;
let applyReady = false;
let noticeTimer = null;
let pendingRollback = null;

const $ = (id) => document.getElementById(id);
const value = (id) => $(id).value.trim();
const numberValue = (id) => Number($(id).value);
const checked = (id) => $(id).checked;

function notify(message, kind = "info", sticky = false) {
  const box = $("notice");
  box.textContent = message;
  box.className = `notice ${kind}`;
  if (noticeTimer) clearTimeout(noticeTimer);
  if (!sticky) {
    noticeTimer = setTimeout(() => box.classList.add("hidden"), 7000);
  }
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = { ...(options.headers || {}) };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : String(body || `HTTP ${response.status}`);
    throw new Error(detail);
  }
  return body;
}

function authMethod() {
  return document.querySelector('input[name="auth"]:checked').value;
}

function pcAuthMethod() {
  return document.querySelector('input[name="pc-auth"]:checked').value;
}

function profileName() {
  return document.querySelector('input[name="profile"]:checked').value;
}

function collectConfig() {
  const scopes = [];
  if (checked("scope-cvm")) scopes.push("cvm");
  if (checked("scope-ahv")) scopes.push("ahv");
  if (checked("scope-pcvm")) scopes.push("pcvm");
  return {
    cluster_host: value("cluster-host"),
    ssh_port: numberValue("ssh-port"),
    username: value("username"),
    auth_method: authMethod(),
    password: value("password"),
    private_key: privateKeyText,
    key_passphrase: value("key-passphrase"),
    pc_host: value("pc-host"),
    pc_port: numberValue("pc-port"),
    pc_username: value("pc-username"),
    pc_use_same_auth: checked("pc-same-auth"),
    pc_auth_method: pcAuthMethod(),
    pc_password: value("pc-password"),
    pc_private_key: pcPrivateKeyText,
    pc_key_passphrase: value("pc-key-passphrase"),
    profile: profileName(),
    scopes,
    full_health_check: checked("full-health"),
    command_timeout: numberValue("command-timeout"),
    verification_timeout: numberValue("verification-timeout"),
    verification_interval: numberValue("verification-interval"),
    min_name_servers: numberValue("min-dns"),
    min_ntp_servers: numberValue("min-ntp"),
    syslog_enabled: checked("syslog-enabled"),
    syslog_server_name: value("syslog-name"),
    syslog_server_ip: value("syslog-ip"),
    syslog_port: numberValue("syslog-port"),
    syslog_protocol: $("syslog-protocol").value,
    syslog_relp: checked("syslog-relp"),
    syslog_modules: value("syslog-modules"),
    api_enabled: checked("api-enabled"),
    api_host: value("api-host"),
    api_port: numberValue("api-port"),
    api_username: value("api-username"),
    api_password: value("api-password"),
    api_ca_pem: apiCaText,
    api_cluster_ext_id: $("api-result").dataset.extId || ""
  };
}

function fillConfig(config) {
  if (!config) return;
  const mapping = {
    "cluster-host": "cluster_host", "ssh-port": "ssh_port", username: "username",
    "pc-host": "pc_host", "pc-port": "pc_port", "pc-username": "pc_username",
    "command-timeout": "command_timeout", "verification-timeout": "verification_timeout",
    "verification-interval": "verification_interval", "min-dns": "min_name_servers",
    "min-ntp": "min_ntp_servers", "syslog-name": "syslog_server_name",
    "syslog-ip": "syslog_server_ip", "syslog-port": "syslog_port",
    "syslog-modules": "syslog_modules", "api-host": "api_host",
    "api-port": "api_port", "api-username": "api_username"
  };
  Object.entries(mapping).forEach(([id, key]) => {
    if (config[key] !== undefined && config[key] !== null) $(id).value = config[key];
  });
  document.querySelectorAll('input[name="profile"]').forEach((input) => {
    input.checked = input.value === config.profile;
  });
  document.querySelectorAll('input[name="auth"]').forEach((input) => {
    input.checked = input.value === (config.auth_method || "password");
  });
  const keyAuth = (config.auth_method || "password") === "key";
  $("password-auth").classList.toggle("hidden", keyAuth);
  $("key-auth").classList.toggle("hidden", !keyAuth);
  const scopes = config.scopes || [];
  $("scope-cvm").checked = scopes.includes("cvm");
  $("scope-ahv").checked = scopes.includes("ahv");
  $("scope-pcvm").checked = scopes.includes("pcvm");
  $("full-health").checked = config.full_health_check !== false;
  $("syslog-enabled").checked = Boolean(config.syslog_enabled);
  $("syslog-fields").classList.toggle("hidden", !config.syslog_enabled);
  $("syslog-protocol").value = config.syslog_protocol || "tcp";
  $("syslog-relp").checked = config.syslog_relp !== false;
  $("api-enabled").checked = Boolean(config.api_enabled);
  $("api-fields").classList.toggle("hidden", !config.api_enabled);
  $("api-result").dataset.extId = config.api_cluster_ext_id || "";
  $("pc-same-auth").checked = config.pc_use_same_auth !== false;
  $("pc-auth-fields").classList.toggle("hidden", config.pc_use_same_auth !== false);
  document.querySelectorAll('input[name="pc-auth"]').forEach((input) => {
    input.checked = input.value === (config.pc_auth_method || "password");
  });
  const pcKeyAuth = (config.pc_auth_method || "password") === "key";
  $("pc-password-auth").classList.toggle("hidden", pcKeyAuth);
  $("pc-key-auth").classList.toggle("hidden", !pcKeyAuth);
}

function renderContext() {
  const active = bootstrapState && bootstrapState.active_cluster;
  $("active-host").textContent = active ? active.cluster_host : "No cluster selected";
  $("active-meta").textContent = active
    ? `${active.profile || "Profile not set"} · ${(active.scopes || []).join(", ").toUpperCase()}`
    : "Activate a connection to begin.";
  $("close-context-button").classList.toggle("hidden", !active);
  if (active) fillConfig(active);
  renderApplyGate();
}

function renderApplyGate() {
  const gate = bootstrapState && bootstrapState.latest_dry_run;
  const host = bootstrapState && bootstrapState.active_cluster && bootstrapState.active_cluster.cluster_host;
  applyReady = Boolean(gate && gate.apply_ready && gate.cluster_host === host);
  $("open-apply").disabled = !applyReady;
  $("apply-gate-icon").className = `gate-icon ${applyReady ? "ready" : "locked"}`;
  $("apply-gate-icon").textContent = applyReady ? "✓" : "×";
  $("apply-gate-title").textContent = applyReady ? "Assessed plan is ready for approval" : "Apply is locked";
  $("apply-gate-copy").textContent = applyReady
    ? `Dry run ${gate.job_id} passed at ${new Date(gate.completed_at).toLocaleString()}.`
    : (gate && gate.reason) || "Complete a successful full-health dry run.";
}

async function bootstrap() {
  const data = await api("/api/bootstrap");
  csrfToken = data.csrf;
  bootstrapState = data;
  renderContext();
  await Promise.all([loadCapabilities(), loadAudit(), loadManualControls()]);
}

async function fileText(input) {
  const file = input.files && input.files[0];
  return file ? await file.text() : "";
}

async function inspectHostKey() {
  return inspectHostKeyFor(value("cluster-host"), numberValue("ssh-port"));
}

async function inspectPcHostKey() {
  return inspectHostKeyFor(value("pc-host"), numberValue("pc-port"));
}

function updateTrustButtonState() {
  $("trust-key").disabled = !inspectedFingerprint || !value("fingerprint-suffix");
}

function invalidateFingerprintInspection() {
  fingerprintInspectionSequence += 1;
  inspectedFingerprint = null;
  $("fingerprint-suffix").value = "";
  $("fingerprint-suffix").placeholder = "";
  $("fingerprint-target").textContent = "Presented fingerprint";
  $("fingerprint-value").textContent = "";
  $("fingerprint-help").textContent = "";
  $("fingerprint-panel").classList.remove("loading");
  $("fingerprint-panel").classList.add("hidden");
  $("inspect-key").disabled = false;
  $("inspect-pc-key").disabled = false;
  updateTrustButtonState();
}

async function inspectHostKeyFor(host, port) {
  const inspectionSequence = ++fingerprintInspectionSequence;
  inspectedFingerprint = null;
  $("fingerprint-suffix").value = "";
  $("fingerprint-suffix").placeholder = "";
  $("fingerprint-target").textContent = `Inspecting ${host}:${port}`;
  $("fingerprint-value").textContent = "Reading the presented host key…";
  $("fingerprint-help").textContent = "The previous fingerprint is no longer selected.";
  $("fingerprint-panel").classList.remove("hidden");
  $("fingerprint-panel").classList.add("loading");
  $("inspect-key").disabled = true;
  $("inspect-pc-key").disabled = true;
  updateTrustButtonState();
  try {
    const result = await api("/api/host-key/inspect", {
      method: "POST",
      body: JSON.stringify({ host, port })
    });
    if (inspectionSequence !== fingerprintInspectionSequence) return;
    inspectedFingerprint = result;
    $("fingerprint-target").textContent = `Presented fingerprint for ${result.host}:${result.port}`;
    $("fingerprint-value").textContent = `${result.algorithm} ${result.fingerprint}`;
    $("fingerprint-help").textContent = result.instruction;
    $("fingerprint-suffix").value = "";
    $("fingerprint-suffix").placeholder = result.verification_suffix;
    updateTrustButtonState();
    $("fingerprint-panel").scrollIntoView({ behavior: "smooth", block: "center" });
    notify("Host key inspected. Verify it independently before trusting.", "info");
  } catch (error) {
    if (inspectionSequence !== fingerprintInspectionSequence) return;
    $("fingerprint-target").textContent = `No fingerprint selected for ${host}:${port}`;
    $("fingerprint-value").textContent = "Inspection failed";
    $("fingerprint-help").textContent = "Correct the connection details and inspect this host again.";
    notify(error.message, "error", true);
  } finally {
    if (inspectionSequence === fingerprintInspectionSequence) {
      $("fingerprint-panel").classList.remove("loading");
      $("inspect-key").disabled = false;
      $("inspect-pc-key").disabled = false;
      updateTrustButtonState();
    }
  }
}

async function trustHostKey() {
  if (!inspectedFingerprint) return;
  try {
    await api("/api/host-key/trust", {
      method: "POST",
      body: JSON.stringify({
        host: inspectedFingerprint.host,
        port: inspectedFingerprint.port,
        fingerprint: inspectedFingerprint.fingerprint,
        verification_suffix: value("fingerprint-suffix")
      })
    });
    invalidateFingerprintInspection();
    $("connection-status").textContent = "Host key trusted; connection not tested";
    notify("SSH host key added to this app's private trust store.", "success");
  } catch (error) {
    notify(error.message, "error", true);
  }
}

async function testConnection() {
  const button = $("test-connection");
  button.disabled = true;
  $("connection-status").textContent = "Testing…";
  try {
    const result = await api("/api/connection/test", {
      method: "POST", body: JSON.stringify(collectConfig())
    });
    $("connection-status").textContent = `${result.cluster_name}: SSH and nCLI verified`;
    notify("Connection succeeded. No cluster changes were made.", "success");
  } catch (error) {
    $("connection-status").textContent = "Connection failed";
    notify(error.message, "error", true);
  } finally {
    button.disabled = false;
  }
}

async function testPcConnection() {
  const button = $("test-pc-connection");
  button.disabled = true;
  $("pc-connection-status").textContent = "Testing…";
  try {
    const data = collectConfig();
    data.cluster_host = data.pc_host;
    data.ssh_port = data.pc_port;
    data.username = data.pc_username;
    if (!data.pc_use_same_auth) {
      data.auth_method = data.pc_auth_method;
      data.password = data.pc_password;
      data.private_key = data.pc_private_key;
      data.key_passphrase = data.pc_key_passphrase;
    }
    data.scopes = ["cvm"];
    const result = await api("/api/connection/test", {
      method: "POST", body: JSON.stringify(data)
    });
    $("pc-connection-status").textContent = `${result.cluster_name}: SSH and nCLI verified`;
    notify("PCVM connection succeeded. No remote changes were made.", "success");
  } catch (error) {
    $("pc-connection-status").textContent = "Connection failed";
    notify(error.message, "error", true);
  } finally {
    button.disabled = false;
  }
}

async function testV4() {
  const resultBox = $("api-result");
  try {
    const result = await api("/api/v4/cluster-identity", {
      method: "POST",
      body: JSON.stringify({
        api_host: value("api-host"),
        api_port: numberValue("api-port"),
        api_username: value("api-username"),
        api_password: value("api-password"),
        api_ca_pem: apiCaText
      })
    });
    resultBox.replaceChildren();
    const message = document.createElement("p");
    message.textContent = result.clusters.length
      ? `v4.2 identity verified for ${result.clusters.length} cluster(s). Read-only inventory; credentials were not saved.`
      : "v4.2 connected, but no clusters were returned for this account.";
    resultBox.appendChild(message);
    if (result.clusters.length) {
      const select = document.createElement("select");
      const prompt = document.createElement("option");
      prompt.value = "";
      prompt.textContent = result.clusters.length === 1 ? "Verified cluster" : "Select the one active cluster";
      select.appendChild(prompt);
      result.clusters.forEach((item) => {
        const option = document.createElement("option");
        option.value = item.ext_id;
        option.textContent = `${item.name}${item.ext_id ? ` (${item.ext_id})` : ""}`;
        select.appendChild(option);
      });
      if (result.clusters.length === 1) select.value = result.clusters[0].ext_id;
      resultBox.dataset.extId = select.value;
      select.addEventListener("change", () => { resultBox.dataset.extId = select.value; });
      resultBox.appendChild(select);
    } else {
      resultBox.dataset.extId = "";
    }
    resultBox.classList.remove("hidden");
    notify("Nutanix v4.2 API identity check succeeded.", "success");
  } catch (error) {
    resultBox.classList.add("hidden");
    notify(error.message, "error", true);
  }
}

async function activateConfig() {
  try {
    const result = await api("/api/configuration/activate", {
      method: "POST", body: JSON.stringify(collectConfig())
    });
    bootstrapState.active_cluster = result.active_cluster;
    $("config-status").textContent = `Active · ${result.fingerprint.slice(0, 12)}`;
    renderContext();
    notify("Configuration activated. Secrets were not saved.", "success");
  } catch (error) {
    notify(error.message, "error", true);
  }
}

function totalsFromReport(report) {
  const totals = { planned: 0, applied: 0, verified: 0, failed: 0, skipped: 0 };
  (report.targets || []).forEach((target) => {
    const scopes = Object.values(target.scopes || {});
    scopes.forEach((scope) => {
      Object.keys(totals).forEach((key) => totals[key] += Number(scope[key] || 0));
    });
    if (!scopes.length) totals.failed += Number(target.failures || 0);
  });
  return totals;
}

function targetStatusesFromReport(report) {
  const labels = { cluster: "Cluster", prism_central: "Prism Central" };
  const statuses = {
    complete: "complete",
    completed_with_findings: "completed with findings",
    connection_failed: "connection failed",
    execution_failed: "remote execution failed",
    not_attempted: "not attempted"
  };
  return (report.targets || []).map((target) => {
    let status = target.status;
    if (!status) {
      status = target.error
        ? `${target.phase || "target"}_failed`
        : target.preflight === "PASS" ? "complete" : "completed_with_findings";
    }
    return {
      label: labels[target.type] || target.type || "Target",
      host: target.host || "unknown host",
      status,
      statusText: statuses[status] || status.replaceAll("_", " "),
      detail: target.error || (target.findings || [])[0] || "",
      reportPath: target.report_path || "",
      jsonReportPath: target.json_report_path || "",
      csvLog: target.csv_log || ""
    };
  });
}

function renderJob(job) {
  currentJob = job;
  $("job-panel").classList.remove("hidden");
  $("job-mode").textContent = job.mode.replaceAll("_", " ");
  $("job-state").textContent = job.status === "running" ? "Operation in progress" : job.status;
  $("job-id").textContent = job.id;
  $("job-progress").className = job.status === "running" ? "" : job.status === "succeeded" ? "done" : "failed";
  if (job.console_tail) {
    $("job-console").textContent = job.console_tail;
    $("job-console").classList.remove("hidden");
  }
  if (job.status === "running") return;

  const report = job.report || {};
  const totals = totalsFromReport(report);
  const result = $("job-result");
  result.replaceChildren();
  const heading = document.createElement("h3");
  heading.textContent = job.status === "succeeded"
    ? `${job.mode.replaceAll("_", " ")} completed`
    : `${job.mode.replaceAll("_", " ")} needs attention`;
  result.appendChild(heading);
  if (report.fatal_error || job.failure) {
    const error = document.createElement("p");
    error.textContent = report.fatal_error || job.failure;
    error.className = "field-note";
    result.appendChild(error);
  }
  const targetStatuses = targetStatusesFromReport(report);
  if (targetStatuses.length) {
    const targetList = document.createElement("div");
    targetList.className = "target-status-list";
    targetStatuses.forEach((target) => {
      const item = document.createElement("div");
      item.className = `target-status ${target.status === "complete" ? "ok" : "attention"}`;
      const title = document.createElement("b");
      title.textContent = `${target.label}: ${target.statusText}`;
      const host = document.createElement("span");
      host.textContent = target.host;
      item.append(title, host);
      if (target.detail) {
        const detail = document.createElement("p");
        detail.textContent = target.detail;
        item.appendChild(detail);
      }
      if (target.reportPath || target.jsonReportPath || target.csvLog) {
        const evidence = document.createElement("small");
        evidence.textContent = [
          target.reportPath ? `Text report: ${target.reportPath}` : "",
          target.jsonReportPath ? `JSON report: ${target.jsonReportPath}` : "",
          target.csvLog ? `CSV: ${target.csvLog}` : ""
        ].filter(Boolean).join(" · ");
        item.appendChild(evidence);
      }
      targetList.appendChild(item);
    });
    result.appendChild(targetList);
  }
  const metrics = document.createElement("div");
  metrics.className = "metric-grid";
  Object.entries(totals).forEach(([name, count]) => {
    const item = document.createElement("div");
    item.className = "metric";
    const countEl = document.createElement("b");
    countEl.textContent = String(count);
    const nameEl = document.createElement("span");
    nameEl.textContent = name;
    item.append(countEl, nameEl);
    metrics.appendChild(item);
  });
  result.appendChild(metrics);
  const actions = document.createElement("div");
  actions.className = "result-actions";
  if (job.evidence_file) {
    const download = document.createElement("a");
    download.href = `/api/jobs/${job.id}/evidence`;
    download.className = "button-link";
    download.textContent = "Download evidence package";
    actions.appendChild(download);
  }
  if (job.rollback_manifests && job.rollback_manifests.length) {
    const note = document.createElement("span");
    note.className = "inline-status";
    note.textContent = `${job.rollback_manifests.length} rollback manifest(s) captured.`;
    actions.appendChild(note);
  }
  if (job.mode === "ROLLBACK_PREVIEW" && job.status === "succeeded") {
    const rollback = document.createElement("button");
    rollback.type = "button";
    rollback.className = "danger";
    rollback.textContent = "Review and apply rollback";
    rollback.addEventListener("click", () => openRollbackDialog({
      source_job_id: job.source_job_id,
      manifest_name: job.manifest_name
    }));
    actions.appendChild(rollback);
  }
  result.appendChild(actions);
}

async function pollJob(jobId) {
  try {
    const job = await api(`/api/jobs/${jobId}`);
    renderJob(job);
    if (job.status === "running") {
      setTimeout(() => pollJob(jobId), 1800);
      return;
    }
    await bootstrap();
    notify(
      job.status === "succeeded" ? "Operation completed. Review and download the evidence." : "Operation completed with issues. Review the report before proceeding.",
      job.status === "succeeded" ? "success" : "error",
      job.status !== "succeeded"
    );
  } catch (error) {
    notify(error.message, "error", true);
  }
}

async function startDryRun() {
  $("run-dry").disabled = true;
  try {
    const job = await api("/api/operations/dry-run", {
      method: "POST", body: JSON.stringify(collectConfig())
    });
    renderJob(job);
    notify("Dry assessment started. The cluster will not be changed.", "info");
    pollJob(job.id);
  } catch (error) {
    notify(error.message, "error", true);
  } finally {
    $("run-dry").disabled = false;
  }
}

function openApplyDialog() {
  const host = bootstrapState.active_cluster.cluster_host;
  $("apply-phrase").textContent = `APPLY ${host}`;
  $("typed-confirmation").value = "";
  $("apply-dialog").showModal();
}

async function confirmApply(event) {
  event.preventDefault();
  try {
    const data = {
      ...collectConfig(),
      approval_id: value("approval-id"),
      typed_confirmation: value("typed-confirmation"),
      ack_backup: checked("ack-backup"),
      ack_window: checked("ack-window"),
      ack_authorized: checked("ack-authorized")
    };
    const job = await api("/api/operations/apply", {
      method: "POST", body: JSON.stringify(data)
    });
    $("apply-dialog").close();
    renderJob(job);
    location.hash = "#dry-run";
    notify("Approved change started. Verification readback is part of this operation.", "info", true);
    pollJob(job.id);
  } catch (error) {
    notify(error.message, "error", true);
  }
}

async function previewRollback(entry, manifestName) {
  try {
    const job = await api("/api/operations/rollback", {
      method: "POST",
      body: JSON.stringify({
        ...collectConfig(),
        source_job_id: entry.id,
        manifest_name: manifestName,
        apply_rollback: false
      })
    });
    renderJob(job);
    location.hash = "#dry-run";
    notify("Rollback preview started. No cluster values will be changed.", "info");
    pollJob(job.id);
  } catch (error) {
    notify(error.message, "error", true);
  }
}

function openRollbackDialog(rollback) {
  pendingRollback = rollback;
  const host = bootstrapState.active_cluster.cluster_host;
  $("rollback-phrase").textContent = `ROLLBACK ${host}`;
  $("rollback-confirmation").value = "";
  $("rollback-dialog").showModal();
}

async function confirmRollback(event) {
  event.preventDefault();
  if (!pendingRollback) return;
  try {
    const job = await api("/api/operations/rollback", {
      method: "POST",
      body: JSON.stringify({
        ...collectConfig(),
        ...pendingRollback,
        apply_rollback: true,
        approval_id: value("rollback-approval-id"),
        typed_confirmation: value("rollback-confirmation"),
        ack_backup: checked("rollback-ack-backup"),
        ack_window: checked("rollback-ack-window"),
        ack_authorized: checked("rollback-ack-authorized")
      })
    });
    $("rollback-dialog").close();
    renderJob(job);
    location.hash = "#dry-run";
    notify("Approved rollback started. Restored values will be verified by readback.", "info", true);
    pollJob(job.id);
  } catch (error) {
    notify(error.message, "error", true);
  }
}

async function loadCapabilities() {
  const data = await api("/api/capabilities");
  const canList = $("can-list");
  canList.replaceChildren();
  data.automates.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    canList.appendChild(li);
  });
  const cannot = $("cannot-list");
  cannot.replaceChildren();
  data.does_not_automate.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "cannot-item";
    const title = document.createElement("b");
    title.textContent = entry.item;
    const why = document.createElement("span");
    why.textContent = entry.why;
    item.append(title, why);
    cannot.appendChild(item);
  });
}

async function loadAudit() {
  const data = await api("/api/audit");
  const list = $("audit-list");
  list.replaceChildren();
  $("audit-summary").textContent = data.entries.length
    ? `${data.entries.length} operation(s) for ${data.active_cluster}.`
    : "No operations yet for the active workspace.";
  data.entries.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "audit-entry";
    const mode = document.createElement("span");
    mode.className = "mode";
    mode.textContent = entry.mode.replaceAll("_", " ");
    const detail = document.createElement("div");
    const title = document.createElement("b");
    title.textContent = `${entry.profile} · ${(entry.scopes || []).join(", ").toUpperCase()}`;
    const time = document.createElement("small");
    time.textContent = `${new Date(entry.completed_at).toLocaleString()} · ${entry.id}`;
    detail.append(title, time);
    const right = document.createElement("div");
    const tag = document.createElement("span");
    tag.className = `tag ${entry.status}`;
    tag.textContent = entry.status;
    right.appendChild(tag);
    if (entry.evidence_file) {
      const link = document.createElement("a");
      link.href = `/api/jobs/${entry.id}/evidence`;
      link.textContent = "Evidence";
      link.className = "audit-link";
      right.appendChild(document.createTextNode(" "));
      right.appendChild(link);
    }
    if (entry.rollback_manifests && entry.rollback_manifests.length) {
      const preview = document.createElement("button");
      preview.type = "button";
      preview.className = "link-button";
      preview.textContent = "Preview rollback";
      preview.addEventListener("click", () => previewRollback(entry, entry.rollback_manifests[0]));
      right.appendChild(preview);
    }
    row.append(mode, detail, right);
    list.appendChild(row);
  });
}

async function loadManualControls() {
  const data = await api("/api/manual-controls");
  const list = $("manual-controls");
  list.replaceChildren();
  data.controls.forEach((control) => {
    const item = document.createElement("div");
    item.className = "manual-item";
    const text = document.createElement("p");
    text.textContent = control.control;
    const select = document.createElement("select");
    [
      ["not_started", "Not started"], ["in_progress", "In progress"],
      ["complete", "Complete"], ["accepted_risk", "Accepted risk"]
    ].forEach(([optionValue, label]) => {
      const option = document.createElement("option");
      option.value = optionValue;
      option.textContent = label;
      option.selected = optionValue === control.status;
      select.appendChild(option);
    });
    const note = document.createElement("textarea");
    note.placeholder = "Evidence reference, owner, reason, or next step";
    note.value = control.note || "";
    const actions = document.createElement("div");
    actions.className = "manual-actions";
    const save = document.createElement("button");
    save.type = "button";
    save.className = "secondary";
    save.textContent = "Save status";
    save.addEventListener("click", async () => {
      try {
        await api("/api/manual-controls", {
          method: "POST",
          body: JSON.stringify({ index: control.index, status: select.value, note: note.value })
        });
        notify("Manual control status saved for this cluster.", "success");
      } catch (error) {
        notify(error.message, "error", true);
      }
    });
    actions.appendChild(save);
    item.append(text, select, note, actions);
    list.appendChild(item);
  });
}

function openCloseDialog() {
  const host = bootstrapState.active_cluster.cluster_host;
  $("close-phrase").textContent = `CLOSE ${host}`;
  $("close-confirmation").value = "";
  $("close-dialog").showModal();
}

async function confirmClose(event) {
  event.preventDefault();
  try {
    const result = await api("/api/context/close", {
      method: "POST", body: JSON.stringify({ confirmation: value("close-confirmation") })
    });
    $("close-dialog").close();
    privateKeyText = "";
    pcPrivateKeyText = "";
    apiCaText = "";
    $("password").value = "";
    $("pc-password").value = "";
    $("pc-key-passphrase").value = "";
    $("api-password").value = "";
    await bootstrap();
    notify(`${result.archived_cluster} closed. Evidence remains on this workstation.`, "success");
  } catch (error) {
    notify(error.message, "error", true);
  }
}

function wireEvents() {
  document.querySelectorAll('input[name="auth"]').forEach((input) => input.addEventListener("change", () => {
    const key = authMethod() === "key";
    $("password-auth").classList.toggle("hidden", key);
    $("key-auth").classList.toggle("hidden", !key);
  }));
  $("private-key-file").addEventListener("change", async (event) => {
    privateKeyText = await fileText(event.target);
  });
  $("pc-private-key-file").addEventListener("change", async (event) => {
    pcPrivateKeyText = await fileText(event.target);
  });
  $("pc-same-auth").addEventListener("change", () => {
    $("pc-auth-fields").classList.toggle("hidden", checked("pc-same-auth"));
  });
  document.querySelectorAll('input[name="pc-auth"]').forEach((input) => input.addEventListener("change", () => {
    const key = pcAuthMethod() === "key";
    $("pc-password-auth").classList.toggle("hidden", key);
    $("pc-key-auth").classList.toggle("hidden", !key);
  }));
  $("api-ca-file").addEventListener("change", async (event) => {
    apiCaText = await fileText(event.target);
  });
  $("api-enabled").addEventListener("change", () => {
    $("api-fields").classList.toggle("hidden", !checked("api-enabled"));
    if (!value("api-host")) $("api-host").value = value("cluster-host");
  });
  $("syslog-enabled").addEventListener("change", () => {
    $("syslog-fields").classList.toggle("hidden", !checked("syslog-enabled"));
  });
  $("inspect-key").addEventListener("click", inspectHostKey);
  $("inspect-pc-key").addEventListener("click", inspectPcHostKey);
  $("trust-key").addEventListener("click", trustHostKey);
  $("fingerprint-suffix").addEventListener("input", updateTrustButtonState);
  ["cluster-host", "ssh-port", "pc-host", "pc-port"].forEach((id) => {
    $(id).addEventListener("input", invalidateFingerprintInspection);
  });
  $("test-connection").addEventListener("click", testConnection);
  $("test-pc-connection").addEventListener("click", testPcConnection);
  $("test-api").addEventListener("click", testV4);
  $("activate-config").addEventListener("click", activateConfig);
  $("run-dry").addEventListener("click", startDryRun);
  $("open-apply").addEventListener("click", openApplyDialog);
  $("confirm-apply").addEventListener("click", confirmApply);
  $("refresh-audit").addEventListener("click", async () => {
    await Promise.all([loadAudit(), loadManualControls()]);
    notify("Audit refreshed.", "success");
  });
  $("close-context-button").addEventListener("click", openCloseDialog);
  $("confirm-close").addEventListener("click", confirmClose);
  $("confirm-rollback").addEventListener("click", confirmRollback);
}

document.addEventListener("DOMContentLoaded", async () => {
  wireEvents();
  try {
    await bootstrap();
  } catch (error) {
    notify(`Control Center could not initialize: ${error.message}`, "error", true);
  }
});
