"use strict";

let csrfToken = "";
let currentStatus = null;
let activeJobId = null;
let pollTimer = null;

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = { ...(options.headers || {}) };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, {
    ...options,
    method,
    headers,
    credentials: "same-origin"
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
  return body;
}

function actionRunning(status) {
  const job = status && status.current_job;
  return Boolean(job && ["queued", "running"].includes(job.status));
}

function renderStatus(status) {
  currentStatus = status;
  const busy = actionRunning(status);
  const running = Boolean(status.app.running);
  $("status-pill").textContent = status.state;
  $("status-pill").dataset.state = status.state;
  $("status-detail").textContent = status.last_error
    || (running ? `Available at ${status.app.url}` : "The hardening interface is not running.");
  $("registration-status").textContent = status.registration.registered
    ? `Automatic login start: ${status.registration.kind}`
    : "Automatic login start is not registered.";
  $("dependency-status").textContent = status.dependencies_ready ? "Ready" : "Not installed";
  $("cluster-status").textContent = status.app.active_cluster || "None";
  $("operation-status").textContent = status.app.operation_running ? "Cluster operation running" : "Idle";
  $("version").textContent = `Nutanix STIG Control Center ${status.version}`;

  $("install-button").disabled = busy;
  $("repair-button").disabled = busy || status.app.operation_running;
  $("start-button").disabled = busy || running;
  $("stop-button").disabled = busy || !running || status.app.operation_running;
  $("restart-button").disabled = busy || status.app.operation_running;
  $("open-button").disabled = busy || !running || !status.app.url;
  $("uninstall-button").disabled = busy || status.app.operation_running;
}

function renderJob(job) {
  $("job-card").classList.remove("hidden");
  $("job-title").textContent = job.action.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  $("job-state").textContent = job.status;
  $("job-progress").textContent = (job.progress || []).map((entry) => entry.message).join("\n");
  $("job-progress").scrollTop = $("job-progress").scrollHeight;
  $("progress-bar").className = job.status === "succeeded" ? "done" : (job.status === "failed" ? "failed" : "");
  $("job-result").textContent = job.error || (job.result && job.result.message) || "";
}

async function refreshStatus() {
  try {
    renderStatus(await api("/api/status"));
  } catch (error) {
    $("status-pill").textContent = "Error";
    $("status-pill").dataset.state = "Error";
    $("status-detail").textContent = error.message;
  }
}

async function pollJob() {
  if (!activeJobId) return;
  try {
    const job = await api(`/api/jobs/${activeJobId}`);
    renderJob(job);
    await refreshStatus();
    if (["succeeded", "failed"].includes(job.status)) {
      activeJobId = null;
      if (job.action === "uninstall" && job.status === "succeeded") {
        clearInterval(pollTimer);
        $("status-detail").textContent = "Supervisor registration removed. This page will close.";
      }
    }
  } catch (error) {
    $("job-result").textContent = error.message;
  }
}

async function runAction(action) {
  try {
    const job = await api(`/api/actions/${action}`, {
      method: "POST",
      body: "{}"
    });
    activeJobId = job.id;
    renderJob(job);
    await refreshStatus();
  } catch (error) {
    $("job-card").classList.remove("hidden");
    $("job-title").textContent = "Action blocked";
    $("job-state").textContent = "failed";
    $("progress-bar").className = "failed";
    $("job-result").textContent = error.message;
  }
}

function openControlCenter() {
  if (currentStatus && currentStatus.app.url) {
    window.open(currentStatus.app.url, "_blank", "noopener");
  }
}

async function bootstrap() {
  const data = await api("/api/bootstrap");
  csrfToken = data.csrf;
  renderStatus(data.status);
  pollTimer = setInterval(async () => {
    if (activeJobId) await pollJob();
    else await refreshStatus();
  }, 2500);
}

$("install-button").addEventListener("click", () => runAction("install"));
$("repair-button").addEventListener("click", () => {
  if (window.confirm("Repair rebuilds the private Python environment. Evidence and settings are preserved. Continue?")) {
    runAction("repair");
  }
});
$("start-button").addEventListener("click", () => runAction("start"));
$("stop-button").addEventListener("click", () => runAction("stop"));
$("restart-button").addEventListener("click", () => runAction("restart"));
$("open-button").addEventListener("click", openControlCenter);
$("uninstall-button").addEventListener("click", () => {
  if (window.confirm("Remove automatic supervisor startup and stop the Control Center? Evidence and settings will be preserved.")) {
    runAction("uninstall");
  }
});

bootstrap().catch((error) => {
  $("status-pill").textContent = "Error";
  $("status-pill").dataset.state = "Error";
  $("status-detail").textContent = error.message;
});
