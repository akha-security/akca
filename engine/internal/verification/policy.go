package verification

import (
	"net/url"
	"strings"
)

// requiresClassSpecificProof prevents generic response differences from being
// promoted into injection findings. OAST, executed DOM XSS, calibrated timing,
// or typed replay plus a clean negative control are accepted proof paths.
func requiresClassSpecificProof(candidate Candidate) bool {
	if strings.TrimSpace(candidate.Signal) == "" {
		return false
	}
	if strings.TrimSpace(candidate.ProofPolicyVersion) == "" {
		// Compatibility for callers that construct raw pre-policy candidates:
		// preserve the historical hard gate for server-side fetch/read classes.
		// Scanner-produced candidates always carry a policy version and use the
		// complete catalog below.
		switch candidateModule(candidate) {
		case "ssrf", "xxe", "lfi":
			return true
		default:
			return false
		}
	}
	_, exists := ProofPolicy(candidateModule(candidate))
	return exists
}

func hasClassSpecificProof(candidate Candidate, result Result) bool {
	if strings.TrimSpace(candidate.ProofPolicyVersion) == "" {
		return inferProofType(candidate, result) != ProofNone
	}
	_, satisfied := evaluateProofPolicy(candidate, result)
	return satisfied
}

func validBooleanPairProof(proof *BooleanPairProof) bool {
	if proof == nil || !proof.SameSurface || !proof.SyntaxControlOK ||
		(proof.Orientation != 1 && proof.Orientation != -1) {
		return false
	}
	for _, hash := range []string{
		proof.BaselineHash, proof.FirstTrueHash, proof.FirstFalseHash, proof.ReplayTrueHash, proof.ReplayFalseHash,
		proof.SecondTrueHash, proof.SecondFalseHash, proof.SyntaxControlHash,
	} {
		if strings.TrimSpace(hash) == "" {
			return false
		}
	}
	if proof.FirstTrueHash != proof.ReplayTrueHash ||
		proof.FirstFalseHash != proof.ReplayFalseHash ||
		proof.FirstTrueHash != proof.SecondTrueHash ||
		proof.FirstFalseHash != proof.SecondFalseHash ||
		proof.SyntaxControlHash != proof.BaselineHash ||
		proof.FirstTrueHash == proof.FirstFalseHash {
		return false
	}
	if proof.Orientation == 1 {
		return proof.FirstTrueHash == proof.BaselineHash &&
			proof.FirstFalseHash != proof.BaselineHash
	}
	return proof.FirstFalseHash == proof.BaselineHash &&
		proof.FirstTrueHash != proof.BaselineHash
}

func validOASTCorrelation(candidate Candidate) bool {
	cor := candidate.OAST
	if cor == nil || strings.TrimSpace(cor.PayloadID) == "" || strings.TrimSpace(cor.ScanID) == "" {
		return false
	}
	if strings.TrimSpace(candidate.ScanID) == "" || cor.ScanID != candidate.ScanID {
		return false
	}
	if !sameEndpoint(cor.EndpointURL, candidate.EndpointURL) {
		return false
	}
	if cor.VulnClass != "" && candidateModule(candidate) != "" &&
		!strings.EqualFold(cor.VulnClass, candidateModule(candidate)) {
		return false
	}
	if cor.Parameter != "" && candidate.Parameter != "" && cor.Parameter != candidate.Parameter {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(cor.CallbackURL))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

func sameEndpoint(a, b string) bool {
	ua, errA := url.Parse(strings.TrimSpace(a))
	ub, errB := url.Parse(strings.TrimSpace(b))
	if errA != nil || errB != nil || ua.Hostname() == "" || ub.Hostname() == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) &&
		strings.TrimSuffix(ua.EscapedPath(), "/") == strings.TrimSuffix(ub.EscapedPath(), "/")
}
