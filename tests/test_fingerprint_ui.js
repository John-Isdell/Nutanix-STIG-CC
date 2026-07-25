"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class ClassList {
  constructor(...names) {
    this.names = new Set(names);
  }

  add(name) {
    this.names.add(name);
  }

  remove(name) {
    this.names.delete(name);
  }

  toggle(name, force) {
    if (force === undefined) {
      if (this.names.has(name)) this.names.delete(name);
      else this.names.add(name);
      return;
    }
    if (force) this.names.add(name);
    else this.names.delete(name);
  }

  contains(name) {
    return this.names.has(name);
  }
}

function createElement({ classes = [], value = "" } = {}) {
  const listeners = new Map();
  return {
    checked: false,
    children: [],
    classList: new ClassList(...classes),
    className: "",
    dataset: {},
    disabled: false,
    files: [],
    placeholder: "",
    textContent: "",
    value,
    addEventListener(type, callback) {
      const callbacks = listeners.get(type) || [];
      callbacks.push(callback);
      listeners.set(type, callbacks);
    },
    dispatch(type) {
      for (const callback of listeners.get(type) || []) {
        callback({ target: this });
      }
    },
    append(...children) {
      this.children.push(...children);
    },
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...children) {
      this.children = [...children];
    },
    scrollIntoView() {},
  };
}

function jsonResponse(body) {
  return {
    ok: true,
    headers: { get: () => "application/json" },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function createHarness() {
  const elements = {
    "cluster-host": createElement({ value: "host-a.example.test" }),
    "ssh-port": createElement({ value: "22" }),
    "pc-host": createElement({ value: "host-b.example.test" }),
    "pc-port": createElement({ value: "2222" }),
    "fingerprint-panel": createElement({ classes: ["fingerprint", "hidden"] }),
    "fingerprint-suffix": createElement(),
    "fingerprint-target": createElement(),
    "fingerprint-value": createElement(),
    "fingerprint-help": createElement(),
    "inspect-key": createElement(),
    "inspect-pc-key": createElement(),
    "trust-key": createElement(),
    "api-auth-basic": createElement({ value: "basic" }),
    "api-auth-key": createElement({ value: "api_key" }),
    "api-basic-auth": createElement(),
    "api-key-auth": createElement({ classes: ["hidden"] }),
    "api-host": createElement({ value: "pc.example.test" }),
    "api-port": createElement({ value: "9440" }),
    "api-username": createElement({ value: "viewer" }),
    "api-password": createElement({ value: "basic-secret" }),
    "api-key": createElement({ value: "api-key-secret" }),
    "api-result": createElement({ classes: ["hidden"] }),
    notice: createElement(),
  };
  elements["api-auth-basic"].checked = true;
  const responses = [];
  const document = {
    addEventListener() {},
    getElementById(id) {
      if (!elements[id]) elements[id] = createElement();
      return elements[id];
    },
    createElement() {
      return createElement();
    },
    querySelector(selector) {
      if (selector === 'input[name="api-auth"]:checked') {
        return elements["api-auth-key"].checked
          ? elements["api-auth-key"]
          : elements["api-auth-basic"];
      }
      return createElement({ value: "password" });
    },
    querySelectorAll(selector) {
      if (selector === 'input[name="api-auth"]') {
        return [elements["api-auth-basic"], elements["api-auth-key"]];
      }
      return [];
    },
  };
  const context = vm.createContext({
    Boolean,
    Error,
    JSON,
    Number,
    Promise,
    String,
    clearTimeout() {},
    console,
    document,
    fetch() {
      assert.ok(responses.length, "A queued API response is required");
      return responses.shift();
    },
    setTimeout() {
      return 1;
    },
  });
  const scriptPath = path.join(__dirname, "..", "app", "static", "app.js");
  vm.runInContext(fs.readFileSync(scriptPath, "utf8"), context, {
    filename: scriptPath,
  });
  const run = (source) => vm.runInContext(source, context);
  run("wireEvents()");
  return { elements, responses, run };
}

test("switching from cluster host A to PC host B clears A before showing B", async () => {
  const { elements, responses, run } = createHarness();
  const hostA = {
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:AAAAAAAAAAAAAAAA",
    host: "host-a.example.test",
    instruction: "Verify host A independently.",
    port: 22,
    verification_suffix: "AAAAAAAAAAAA",
  };
  const hostB = {
    algorithm: "ssh-ed25519",
    fingerprint: "SHA256:BBBBBBBBBBBBBBBB",
    host: "host-b.example.test",
    instruction: "Verify host B independently.",
    port: 2222,
    verification_suffix: "BBBBBBBBBBBB",
  };

  responses.push(Promise.resolve(jsonResponse(hostA)));
  await run("inspectHostKey()");
  assert.equal(elements["fingerprint-suffix"].placeholder, "AAAAAAAAAAAA");

  elements["fingerprint-suffix"].value = "AAAAAAAAAAAA";
  elements["fingerprint-suffix"].dispatch("input");
  assert.equal(elements["trust-key"].disabled, false);

  const hostBResponse = deferred();
  responses.push(hostBResponse.promise);
  const pendingInspection = run("inspectPcHostKey()");

  assert.equal(elements["fingerprint-suffix"].value, "");
  assert.equal(elements["fingerprint-suffix"].placeholder, "");
  assert.equal(elements["trust-key"].disabled, true);
  assert.equal(elements["fingerprint-panel"].classList.contains("loading"), true);
  assert.equal(elements["fingerprint-value"].textContent, "Reading the presented host key…");

  hostBResponse.resolve(jsonResponse(hostB));
  await pendingInspection;

  assert.equal(elements["fingerprint-suffix"].value, "");
  assert.equal(elements["fingerprint-suffix"].placeholder, "BBBBBBBBBBBB");
  assert.equal(elements["fingerprint-target"].textContent, "Presented fingerprint for host-b.example.test:2222");
  assert.match(elements["fingerprint-value"].textContent, /BBBBBBBBBBBBBBBB/);
  assert.equal(elements["fingerprint-panel"].classList.contains("loading"), false);
  assert.equal(elements["trust-key"].disabled, true);

  elements["fingerprint-suffix"].value = "BBBBBBBBBBBB";
  elements["fingerprint-suffix"].dispatch("input");
  assert.equal(elements["trust-key"].disabled, false);
});

test("partial dry-run report keeps independent target status and failure totals", () => {
  const { elements, run } = createHarness();
  const report = {
    targets: [
      {
        host: "cluster.example.test",
        type: "cluster",
        status: "complete",
        phase: "complete",
        preflight: "PASS",
        failures: 0,
        scopes: {
          cvm: { planned: 2, applied: 0, verified: 0, failed: 0, skipped: 1 }
        }
      },
      {
        host: "pcvm.example.test",
        type: "prism_central",
        status: "connection_failed",
        phase: "connection",
        preflight: "NOT_RUN",
        failures: 1,
        error: "SSH connection failed: timed out",
        report_path: "reports/stig_report_run.txt",
        json_report_path: "reports/stig_report_run.json",
        csv_log: "logs/stig_run_run.csv",
        scopes: {}
      }
    ]
  };

  const statuses = JSON.parse(
    run(`JSON.stringify(targetStatusesFromReport(${JSON.stringify(report)}))`)
  );
  const totals = JSON.parse(
    run(`JSON.stringify(totalsFromReport(${JSON.stringify(report)}))`)
  );

  assert.equal(statuses[0].label, "Cluster");
  assert.equal(statuses[0].statusText, "complete");
  assert.equal(statuses[1].label, "Prism Central");
  assert.equal(statuses[1].statusText, "connection failed");
  assert.match(statuses[1].detail, /timed out/);
  assert.equal(statuses[1].reportPath, "reports/stig_report_run.txt");
  assert.equal(statuses[1].jsonReportPath, "reports/stig_report_run.json");
  assert.equal(totals.planned, 2);
  assert.equal(totals.failed, 1);
  assert.equal(totals.skipped, 1);

  run(`renderJob(${JSON.stringify({
    id: "partial-run",
    mode: "DRY_RUN",
    status: "failed",
    report
  })})`);
  const targetList = elements["job-result"].children.find(
    (child) => child.className === "target-status-list"
  );
  assert.ok(targetList);
  assert.equal(targetList.children.length, 2);
  assert.equal(targetList.children[0].children[0].textContent, "Cluster: complete");
  assert.equal(
    targetList.children[1].children[0].textContent,
    "Prism Central: connection failed"
  );
});

test("API auth selection sends only the selected ephemeral credential", () => {
  const { elements, run } = createHarness();

  const basic = JSON.parse(run("JSON.stringify(apiIdentityPayload())"));
  assert.equal(basic.api_auth_method, "basic");
  assert.equal(basic.api_username, "viewer");
  assert.equal(basic.api_password, "basic-secret");
  assert.equal(basic.api_key, "");

  elements["api-auth-basic"].checked = false;
  elements["api-auth-key"].checked = true;
  elements["api-auth-key"].dispatch("change");

  assert.equal(elements["api-password"].value, "");
  assert.equal(elements["api-key"].disabled, false);
  assert.equal(elements["api-username"].disabled, true);
  assert.equal(elements["api-basic-auth"].classList.contains("hidden"), true);
  assert.equal(elements["api-key-auth"].classList.contains("hidden"), false);

  const apiKey = JSON.parse(run("JSON.stringify(apiIdentityPayload())"));
  assert.equal(apiKey.api_auth_method, "api_key");
  assert.equal(apiKey.api_username, "");
  assert.equal(apiKey.api_password, "");
  assert.equal(apiKey.api_key, "api-key-secret");
});
