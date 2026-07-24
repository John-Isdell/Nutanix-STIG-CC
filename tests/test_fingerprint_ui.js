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
    notice: createElement(),
  };
  const responses = [];
  const document = {
    addEventListener() {},
    getElementById(id) {
      if (!elements[id]) elements[id] = createElement();
      return elements[id];
    },
    querySelector() {
      return createElement({ value: "password" });
    },
    querySelectorAll() {
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
