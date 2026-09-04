package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var grpcReflectionPaths = []string{
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
}

func (r *Runner) runGRPCScan(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("grpc_scan", target); !ok {
		r.emitSkip("grpc_scan", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Host == "" {
		return nil
	}

	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}

	var out []ModuleFinding
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	// Test 1: Check if current target endpoint accepts gRPC-Web
	isGRPC := false
	targetHeaders := map[string]string{
		"Content-Type": "application/grpc-web+proto",
		"X-User-Agent": "grpc-web-javascript/0.1",
		"X-Grpc-Web":   "1",
	}
	rr, err := r.client.Do(ctx, "POST", target.EndpointURL, []byte("\x00\x00\x00\x00\x00"), targetHeaders)
	if err == nil {
		ct := strings.ToLower(headerValue(rr.Response.Headers, "Content-Type"))
		grpcStatus := headerValue(rr.Response.Headers, "grpc-status")
		if strings.Contains(ct, "application/grpc") || grpcStatus != "" {
			isGRPC = true
			signal := "grpc_web_surface_detected"
			p := defaultPayload("grpc_scan", signal, target.EndpointURL, signal)
			f := r.verifyAndBuild(ctx, "grpc_scan", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "info"
				f.Title = "gRPC / gRPC-Web Service Endpoint Detected"
				f.Description = fmt.Sprintf("Target endpoint '%s' accepted gRPC-Web framing and responded with gRPC status headers (%s).", target.EndpointURL, grpcStatus)
				r.recordFinding(ctx, &out, f, "grpc_scan", signal)
			}
		}
	}

	// Test 2: Probe gRPC Server Reflection Protocol
	for _, refPath := range grpcReflectionPaths {
		if ctx.Err() != nil {
			break
		}

		refURL := baseURL + refPath
		refRR, refErr := r.client.Do(ctx, "POST", refURL, []byte("\x00\x00\x00\x00\x00"), targetHeaders)
		if refErr != nil {
			continue
		}

		refCT := strings.ToLower(headerValue(refRR.Response.Headers, "Content-Type"))
		refStatus := headerValue(refRR.Response.Headers, "grpc-status")
		// gRPC status 0 (OK) or 12 (UNIMPLEMENTED vs 16 UNAUTHENTICATED) indicates the reflection service exists
		if (strings.Contains(refCT, "application/grpc") && (refStatus == "0" || refStatus == "3" || refStatus == "")) ||
			(refRR.Response.StatusCode == 200 && strings.Contains(refRR.Response.Body, "grpc.reflection")) {
			signal := "grpc_reflection_exposed"
			p := defaultPayload("grpc_scan", signal, refPath, signal)
			f := r.verifyAndBuild(ctx, "grpc_scan", target, p, baseline, refRR, signal, false, false, "", "")
			if f != nil {
				f.Severity = "medium"
				f.Title = "gRPC Server Reflection Protocol Enabled"
				f.Description = fmt.Sprintf("gRPC Server Reflection is enabled on '%s', allowing unauthorized clients to enumerate internal protobuf service definitions and method schemas.", refURL)
				r.recordFinding(ctx, &out, f, "grpc_scan", signal)
				break
			}
		}
	}

	_ = isGRPC
	return out
}

func grpcSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	contentType := strings.ToLower(headerValue(response.Headers, "Content-Type"))
	grpcStatus := headerValue(response.Headers, "grpc-status")
	switch signal {
	case "grpc_web_surface_detected":
		return strings.Contains(contentType, "application/grpc") || grpcStatus != ""
	case "grpc_reflection_exposed":
		return (strings.Contains(contentType, "application/grpc") && (grpcStatus == "0" || grpcStatus == "3" || grpcStatus == "")) ||
			(response.StatusCode == 200 && strings.Contains(response.Body, "grpc.reflection"))
	default:
		return false
	}
}
