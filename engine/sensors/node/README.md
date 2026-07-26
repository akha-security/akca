# Akca Node.js Sensor

This optional sensor correlates an Akca DAST probe with runtime source-to-sink
evidence. It does not replace the sensorless scanner.

```js
const express = require("express");
const mysql = require("mysql2");
const { AkcaSensor } = require("@akca-security/node-sensor");

const sensor = new AkcaSensor();
const app = express();
app.use(express.json());
app.use(sensor.middleware());

const db = sensor.instrumentSQL(mysql.createPool(process.env.DATABASE_URL));
```

The Akca collector now starts automatically with every DAST scan. The scanner
sends one discovery request; when this middleware answers it, runtime
correlation is enabled for that host. If `AKCA_SENSOR_URL` is omitted the agent
uses `http://127.0.0.1:19091`. Akca supplies a per-scan token through the
instrumented request, so a pre-shared token is optional. `AKCA_SENSOR_TOKEN`
remains available for fixed-token deployments.

Supported wrappers:

- `instrumentSQL`: raw query concatenation and prepared/bound SQL
- `instrumentCommands`: command execution
- `instrumentFiles`: file access
- `instrumentHTTP`: outbound HTTP/SSRF sinks
- `instrumentTemplates`: template rendering
- `instrumentObject`: custom LDAP, XPath, XML, or deserialization adapters

Only requests carrying a complete Akca correlation envelope are traced. Sink
targets and stack traces are hashed by the collector before persistence.
