"use strict";

const { AsyncLocalStorage } = require("node:async_hooks");
const { createHash, randomUUID, timingSafeEqual } = require("node:crypto");

class AkcaSensor {
  constructor(options = {}) {
    this.collectorURL = String(options.collectorURL || process.env.AKCA_SENSOR_URL || "http://127.0.0.1:19091").replace(/\/$/, "");
    this.token = String(options.token || process.env.AKCA_SENSOR_TOKEN || "");
    this.platform = String(options.platform || "node");
    this.fetch = options.fetch || globalThis.fetch;
    this.storage = new AsyncLocalStorage();
    if (!this.collectorURL || typeof this.fetch !== "function") {
      throw new Error("Akca sensor requires collectorURL and fetch");
    }
    if (this.token && this.token.length < 16) {
      throw new Error("Akca sensor token must contain at least 16 characters");
    }
  }

  middleware() {
    return (req, res, next) => {
      if (getHeader(req, "X-Akca-Sensor-Discovery") === "1") {
        const discoveryToken = getHeader(req, "X-Akca-Sensor-Token");
        if (discoveryToken.length >= 16 && (!this.token || safeEqual(discoveryToken, this.token))) {
          res.setHeader("X-Akca-Sensor", "node/0.1");
        }
        next();
        return;
      }
      const binding = readBinding(req);
      if (!binding) {
        next();
        return;
      }
      const source = readSource(req, binding.parameter, binding.location);
      const context = {
        ...binding,
        traceID: randomUUID(),
        observedAt: new Date().toISOString(),
        source: {
          kind: binding.location,
          name: binding.parameter,
          location: binding.location,
          tainted: source.found,
          value_hash: source.found ? hash(source.value) : ""
        },
        sourceValues: source.found ? [String(source.value)] : [],
        sensorToken: getHeader(req, "X-Akca-Sensor-Token"),
        sinks: [],
        flushed: false
      };
      this.storage.run(context, () => {
        res.once("finish", () => {
          void this.flush(context);
        });
        next();
      });
    };
  }

  recordSink(type, operation, target, options = {}) {
    const context = this.storage.getStore();
    if (!context) return;
    const targetText = stringify(target);
    const parameterText = stringify(options.parameters);
    const targetTainted = containsSource(targetText, context.sourceValues);
    const parameterTainted = containsSource(parameterText, context.sourceValues);
    const sink = {
      type: String(type || "").toLowerCase(),
      operation: String(operation || ""),
      target: targetText,
      tainted: targetTainted || parameterTainted,
      sanitized: Boolean(options.sanitized),
      parameterized: Boolean(options.parameterized || (!targetTainted && parameterTainted)),
      stack: captureStack()
    };
    context.sinks.push(sink);
  }

  instrumentSQL(client, methods = ["query", "execute"]) {
    for (const method of methods) {
      wrapMethod(client, method, (args) => {
        const descriptor = sqlDescriptor(args);
        this.recordSink("sql", method, descriptor.sql, {
          parameters: descriptor.values,
          parameterized: descriptor.parameterized
        });
      });
    }
    return client;
  }

  instrumentCommands(target, methods = ["exec", "execSync", "spawn", "spawnSync"]) {
    return this.instrumentObject(target, methods, "command");
  }

  instrumentFiles(target, methods = ["readFile", "readFileSync", "writeFile", "writeFileSync", "open", "openSync"]) {
    return this.instrumentObject(target, methods, "file");
  }

  instrumentHTTP(target, methods = ["request", "get"]) {
    return this.instrumentObject(target, methods, "http");
  }

  instrumentTemplates(target, methods = ["render", "compile"]) {
    return this.instrumentObject(target, methods, "template");
  }

  instrumentObject(target, methods, sinkType) {
    for (const method of methods) {
      wrapMethod(target, method, (args) => {
        this.recordSink(sinkType, method, args[0], { parameters: args.slice(1) });
      });
    }
    return target;
  }

  async flush(context = this.storage.getStore()) {
    if (!context || context.flushed || context.sinks.length === 0) return false;
    const token = context.sensorToken || this.token;
    if (token.length < 16) return false;
    context.flushed = true;
    const event = {
      trace_id: context.traceID,
      request_id: context.requestID,
      scan_id: context.scanID,
      candidate_id: context.candidateID,
      endpoint: context.endpoint,
      parameter: context.parameter,
      platform: this.platform,
      source: context.source,
      sinks: context.sinks,
      observed_at: context.observedAt
    };
    try {
      const response = await this.fetch(`${this.collectorURL}/v1/traces`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-akca-sensor-token": token
        },
        body: JSON.stringify(event)
      });
      return response.status === 202;
    } catch {
      return false;
    }
  }
}

function readBinding(req) {
  const binding = {
    requestID: getHeader(req, "X-Akca-Request-ID"),
    scanID: getHeader(req, "X-Akca-Scan-ID"),
    candidateID: getHeader(req, "X-Akca-Candidate-ID"),
    endpoint: getHeader(req, "X-Akca-Endpoint"),
    parameter: getHeader(req, "X-Akca-Parameter"),
    location: String(getHeader(req, "X-Akca-Location")).toLowerCase()
  };
  return Object.values(binding).every(Boolean) ? binding : null;
}

function getHeader(req, name) {
  if (typeof req.get === "function") return req.get(name) || "";
  return req.headers?.[name.toLowerCase()] || "";
}

function readSource(req, name, location) {
  let value;
  switch (location) {
    case "header":
      value = typeof req.get === "function" ? req.get(name) : req.headers?.[name.toLowerCase()];
      break;
    case "query":
      value = req.query?.[name];
      break;
    case "json":
    case "form":
    case "body":
      value = readPath(req.body, name);
      break;
    case "cookie":
      value = req.cookies?.[name];
      break;
    default:
      value = readPath(req.params, name) ?? readPath(req.query, name) ?? readPath(req.body, name);
  }
  return { found: value !== undefined && value !== null, value };
}

function readPath(object, dottedPath) {
  if (object === undefined || object === null) return undefined;
  if (Object.prototype.hasOwnProperty.call(object, dottedPath)) return object[dottedPath];
  let current = object;
  for (const part of String(dottedPath).split(".")) {
    if (current === undefined || current === null || !Object.prototype.hasOwnProperty.call(current, part)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function sqlDescriptor(args) {
  if (typeof args[0] === "object" && args[0] !== null) {
    const sql = args[0].sql || args[0].text || "";
    const values = args[0].values ?? args[1];
    return { sql, values, parameterized: hasPlaceholders(sql) && values !== undefined };
  }
  const sql = String(args[0] ?? "");
  const values = args[1];
  return { sql, values, parameterized: hasPlaceholders(sql) && values !== undefined };
}

function hasPlaceholders(sql) {
  return /\?|\$[1-9][0-9]*|:[A-Za-z_][A-Za-z0-9_]*/.test(String(sql));
}

function wrapMethod(target, method, before) {
  if (!target || typeof target[method] !== "function" || target[method].__akcaWrapped) return;
  const original = target[method];
  function wrapped(...args) {
    before(args);
    return Reflect.apply(original, this, args);
  }
  Object.defineProperty(wrapped, "__akcaWrapped", { value: true });
  target[method] = wrapped;
}

function stringify(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function containsSource(value, sources) {
  if (!value) return false;
  return sources.some((source) => source && value.includes(source));
}

function hash(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function safeEqual(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return leftHash.length === rightHash.length && timingSafeEqual(leftHash, rightHash);
}

function captureStack() {
  return String(new Error().stack || "").split("\n").slice(3, 11).map((line) => line.trim());
}

module.exports = { AkcaSensor };
