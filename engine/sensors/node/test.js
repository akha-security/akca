"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { AkcaSensor } = require("./index");

async function captureSQL(sql, values) {
  let captured;
  const sensor = new AkcaSensor({
    collectorURL: "http://127.0.0.1:19091",
    token: "0123456789abcdef",
    fetch: async (_url, options) => {
      captured = JSON.parse(options.body);
      return { status: 202 };
    }
  });
  const client = { query() { return "ok"; } };
  sensor.instrumentSQL(client);
  const req = {
    headers: {
      "x-akca-request-id": "req-1",
      "x-akca-scan-id": "scan-1",
      "x-akca-candidate-id": "candidate-1",
      "x-akca-endpoint": "https://app.test/audit",
      "x-akca-parameter": "x-forwarded-for",
      "x-akca-location": "header",
      "x-forwarded-for": "akca-payload"
    }
  };
  const res = new EventEmitter();
  await new Promise((resolve, reject) => {
    sensor.middleware()(req, res, () => {
      try {
        client.query(sql, values);
        res.emit("finish");
        setImmediate(resolve);
      } catch (error) {
        reject(error);
      }
    });
  });
  return captured;
}

async function captureMultipleSinks() {
  let captured;
  const sensor = new AkcaSensor({
    collectorURL: "http://127.0.0.1:19091",
    token: "0123456789abcdef",
    fetch: async (_url, options) => {
      captured = JSON.parse(options.body);
      return { status: 202 };
    }
  });
  const database = { query() { return "ok"; } };
  const commands = { exec() { return "ok"; } };
  sensor.instrumentSQL(database);
  sensor.instrumentCommands(commands, ["exec"]);
  const req = {
    headers: {
      "x-akca-request-id": "req-multi",
      "x-akca-scan-id": "scan-1",
      "x-akca-candidate-id": "candidate-multi",
      "x-akca-endpoint": "https://app.test/audit",
      "x-akca-parameter": "profile.name",
      "x-akca-location": "json",
      "x-akca-sensor-token": "0123456789abcdef"
    },
    body: { profile: { name: "akca-payload" } }
  };
  const res = new EventEmitter();
  await new Promise((resolve, reject) => {
    sensor.middleware()(req, res, () => {
      try {
        database.query("SELECT 1 WHERE name = ?", ["akca-payload"]);
        commands.exec("echo akca-payload");
        res.emit("finish");
        setImmediate(resolve);
      } catch (error) {
        reject(error);
      }
    });
  });
  return captured;
}

(async () => {
  const discoverySensor = new AkcaSensor({
    collectorURL: "http://127.0.0.1:19091",
    fetch: async () => ({ status: 202 })
  });
  let sensorHeader = "";
  discoverySensor.middleware()({
    headers: {
      "x-akca-sensor-discovery": "1",
      "x-akca-sensor-token": "0123456789abcdef"
    }
  }, {
    setHeader(name, value) {
      if (name.toLowerCase() === "x-akca-sensor") sensorHeader = value;
    }
  }, () => {});
  assert.equal(sensorHeader, "node/0.1");

  const unsafe = await captureSQL("SELECT * FROM audit WHERE ip='akca-payload'");
  assert.equal(unsafe.sinks[0].tainted, true);
  assert.equal(unsafe.sinks[0].parameterized, false);

  const safe = await captureSQL("SELECT * FROM audit WHERE ip = ?", ["akca-payload"]);
  assert.equal(safe.sinks[0].tainted, true);
  assert.equal(safe.sinks[0].parameterized, true);

  const multiple = await captureMultipleSinks();
  assert.equal(multiple.source.tainted, true);
  assert.equal(multiple.sinks.length, 2);
  assert.deepEqual(multiple.sinks.map((sink) => sink.type), ["sql", "command"]);
  process.stdout.write("node sensor tests passed\n");
})().catch((error) => {
  process.stderr.write(`${error.stack}\n`);
  process.exitCode = 1;
});
