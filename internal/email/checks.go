package email

import (
	"bytes"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/jhillyerd/enmime"
)

func CheckDKIM(raw []byte) ([]DKIMResult, error) {
	results, err := dkim.Verify(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	out := make([]DKIMResult, 0, len(results))
	for _, res := range results {
		status := "fail"
		if res.Err == nil {
			status = "pass"
		}
		domain := res.Domain
		selector := res.Identifier
		errStr := ""
		if res.Err != nil {
			errStr = res.Err.Error()
		}
		out = append(out, DKIMResult{Domain: domain, Selector: selector, Status: status, Error: errStr})
	}
	return out, nil
}

func CheckSPF(env *enmime.Envelope, sourceIP, heloDomain string) (SPFResult, error) {
	result := SPFResult{Mechanism: "header"}
	header := env.GetHeader("Received-SPF")
	if header == "" {
		result.Status = "none"
		result.Detail = "no Received-SPF header"
	} else {
		lower := strings.ToLower(header)
		switch {
		case strings.Contains(lower, "pass"):
			result.Status = "pass"
		case strings.Contains(lower, "softfail"):
			result.Status = "softfail"
		case strings.Contains(lower, "fail"):
			result.Status = "fail"
		default:
			result.Status = "neutral"
		}
		result.Detail = header
	}

	if sourceIP != "" {
		ip := net.ParseIP(sourceIP)
		if ip == nil {
			if result.Error == "" {
				result.Error = "invalid source IP"
			}
		} else {
			hosts, err := net.LookupAddr(ip.String())
			if err != nil {
				if result.Error == "" {
					result.Error = err.Error()
				} else {
					result.Error += "; " + err.Error()
				}
			} else if len(hosts) > 0 {
				h := strings.TrimSuffix(hosts[0], ".")
				result.PTR = h
			}
		}
	}
	return result, nil
}

// DKIMResultsFromAuthHeader converts a status string from Authentication-Results into DKIMResult slice.
// Used by the content filter to trust OpenDKIM milter results instead of re-verifying via DNS
// (DNS lookup for igsu.local DKIM TXT records fails in local Docker setups).
func DKIMResultsFromAuthHeader(status string) []DKIMResult {
	if status == "" || status == "none" {
		return nil
	}
	return []DKIMResult{{Status: status}}
}

// SPFResultFromAuthHeader converts a status string from Authentication-Results into SPFResult.
func SPFResultFromAuthHeader(status string) SPFResult {
	return SPFResult{Status: status, Mechanism: "auth-results"}
}

// ParseAuthResults extracts DKIM and SPF results from the Authentication-Results header (RFC 7601).
// This is used when the MTA (Postfix + OpenDKIM + policyd-spf) has already performed the checks.
func ParseAuthResults(env *enmime.Envelope) (dkimStatus, spfStatus string) {
	header := env.GetHeader("Authentication-Results")
	if header == "" {
		return "none", "none"
	}
	lower := strings.ToLower(header)

	// Parse DKIM result
	dkimStatus = "none"
	if idx := strings.Index(lower, "dkim="); idx >= 0 {
		rest := lower[idx+5:]
		end := strings.IndexAny(rest, " ;,\r\n")
		if end > 0 {
			dkimStatus = strings.TrimSpace(rest[:end])
		} else {
			dkimStatus = strings.TrimSpace(rest)
		}
	}

	// Parse SPF result
	spfStatus = "none"
	if idx := strings.Index(lower, "spf="); idx >= 0 {
		rest := lower[idx+4:]
		end := strings.IndexAny(rest, " ;,\r\n")
		if end > 0 {
			spfStatus = strings.TrimSpace(rest[:end])
		} else {
			spfStatus = strings.TrimSpace(rest)
		}
	}

	return dkimStatus, spfStatus
}

func CheckDomainBlocklist(env *enmime.Envelope, blocklist []string) DomainCheck {
	res := DomainCheck{}
	addr := SenderAddress(env)
	parts := strings.Split(addr, "@")
	if len(parts) < 2 {
		res.Domain = addr
		res.Reason = "invalid sender address"
		return res
	}
	domain := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	res.Domain = domain
	for _, bad := range blocklist {
		if domain == strings.ToLower(strings.TrimSpace(bad)) {
			res.Malicious = true
			res.Reason = "sender domain in blocklist"
			return res
		}
	}
	res.Reason = "not in blocklist"
	return res
}
