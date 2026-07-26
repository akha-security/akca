package app

import (
	"context"
	"strings"
)

func (e *Engine) runRuntimeSensorDiscovery(ctx context.Context, targets []string) error {
	if e.platform == nil || e.platform.sensor == nil {
		return nil
	}
	detected := 0
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		rr, err := e.client.Do(ctx, "GET", target, nil, map[string]string{
			"X-Akca-Sensor-Discovery": "1",
			"X-Akca-Sensor-Token":     e.platform.sensor.Token(),
		})
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.ToLower(responseHeader(rr.Response.Headers, "X-Akca-Sensor")), "node/") {
			e.platform.sensor.ActivateEndpoint(target)
			detected++
		}
	}
	return e.Emit("runtime_sensor_discovery_finished", "runtime sensor discovery completed",
		map[string]interface{}{"scan_id": e.currentSession().ID, "targets": len(targets), "active_agents": detected})
}

func responseHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
