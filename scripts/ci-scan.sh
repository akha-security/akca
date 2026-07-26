#!/usr/bin/env bash
set -euo pipefail

if [[ "${AKCA_AUTHORIZED:-}" != "true" ]]; then
  echo "Refusing DAST scan: set AKCA_AUTHORIZED=true only for an explicitly authorized target." >&2
  exit 2
fi

case "${AKCA_TARGET:-}" in
  http://*|https://*) ;;
  *)
    echo "AKCA_TARGET must be an explicit http:// or https:// URL." >&2
    exit 2
    ;;
esac

AKCA_REPORT_PATH="${AKCA_REPORT_PATH:-akca-results.sarif}"
AKCA_RATE_LIMIT="${AKCA_RATE_LIMIT:-10}"
AKCA_CONCURRENCY="${AKCA_CONCURRENCY:-8}"
AKCA_SCAN_ID="${AKCA_SCAN_ID:-akca-ci-${CI_PIPELINE_ID:-${GITHUB_RUN_ID:-${BUILD_NUMBER:-local}}}}"
AKCA_POLICY_GATE="${AKCA_POLICY_GATE:-true}"

if [[ ! -x "./akca" ]]; then
  CGO_ENABLED=0 go -C engine build -buildvcs=false -trimpath -o ../akca ./cmd/akca
fi

./akca \
  --url "${AKCA_TARGET}" \
  --format sarif \
  --output "${AKCA_REPORT_PATH}" \
  --scan-id "${AKCA_SCAN_ID}" \
  --rate-limit "${AKCA_RATE_LIMIT}" \
  --concurrency "${AKCA_CONCURRENCY}"

test -s "${AKCA_REPORT_PATH}"

if [[ "${AKCA_POLICY_GATE}" == "true" ]]; then
  if [[ ! -x "./akca-policy" ]]; then
    CGO_ENABLED=0 go -C engine build -buildvcs=false -trimpath -o ../akca-policy ./cmd/akca-policy
  fi
  policy_args=(--current "${AKCA_SCAN_ID}")
  if [[ -n "${AKCA_BASELINE_SCAN_ID:-}" ]]; then
    policy_args+=(--previous "${AKCA_BASELINE_SCAN_ID}")
  fi
  ./akca-policy "${policy_args[@]}"
fi
