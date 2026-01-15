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
