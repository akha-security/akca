## Summary

Describe the problem and the implemented change.

## Security and evidence model

- What security boundary or behavior does this affect?
- Which positive evidence is required?
- Which negative control or replay prevents false positives?
- Does it send new traffic or change target state?

## Validation

- [ ] Changed Go files are formatted with `gofmt`
- [ ] Positive and safe-negative tests were added or updated
- [ ] `go test ./... -count=1` passes
- [ ] `go vet ./...` passes
- [ ] Documentation and CLI help are accurate
- [ ] No secrets, private target data, generated reports, or binaries are included
