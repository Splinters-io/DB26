package intel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPInfo is an immutable intelligence record for a single IP address.
type IPInfo struct {
	IP         string   `json:"ip"`
	ReverseDNS []string `json:"reverse_dns,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Org        string   `json:"org,omitempty"`
	Country    string   `json:"country,omitempty"`
	City       string   `json:"city,omitempty"`
	Region     string   `json:"region,omitempty"`
	Class      string   `json:"class"` // cdn, public_resolver, corporate, cloud, isp, unknown
}

// ResolverOrigin enriches a candidate with intel about where the DNS lookup came from.
type ResolverOrigin struct {
	CandidateDomain string   `json:"candidate_domain"`
	Headers         []string `json:"headers"`
	ResolverIPs     []IPInfo `json:"resolver_ips"`
	NetworkPath     string   `json:"network_path"` // Summary: "Cloudflare CDN → Google DNS → target"
}

// Cache avoids re-looking up the same IP.
var (
	cache   = make(map[string]IPInfo)
	cacheMu sync.RWMutex
)

// LookupIP gathers intelligence on an IP address.
// Results are cached.
func LookupIP(ip string) IPInfo {
	cacheMu.RLock()
	if info, ok := cache[ip]; ok {
		cacheMu.RUnlock()
		return info
	}
	cacheMu.RUnlock()

	info := IPInfo{IP: ip}

	// Reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil {
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		info.ReverseDNS = names
	}

	// ASN + Geo via ip-api.com (free, no key, 45 req/min)
	fetchIPAPI(&info)

	// Classify
	info.Class = classifyIP(info)

	cacheMu.Lock()
	cache[ip] = info
	cacheMu.Unlock()

	return info
}

// LookupIPs looks up multiple IPs concurrently (max 8 at a time).
func LookupIPs(ips []string) []IPInfo {
	results := make([]IPInfo, len(ips))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			sem <- struct{}{}
			results[idx] = LookupIP(addr)
			<-sem
		}(i, ip)
	}
	wg.Wait()
	return results
}

func fetchIPAPI(info *IPInfo) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org,country,city,regionName", info.IP))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		AS      string `json:"as"`
		Org     string `json:"org"`
		Country string `json:"country"`
		City    string `json:"city"`
		Region  string `json:"regionName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}

	info.ASN = data.AS
	info.Org = data.Org
	info.Country = data.Country
	info.City = data.City
	info.Region = data.Region
}

func classifyIP(info IPInfo) string {
	orgLower := strings.ToLower(info.Org)
	asnLower := strings.ToLower(info.ASN)
	rdns := strings.Join(info.ReverseDNS, " ")
	rdnsLower := strings.ToLower(rdns)

	// CDN
	cdnKeywords := []string{"cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "stackpath", "cdn"}
	for _, kw := range cdnKeywords {
		if strings.Contains(orgLower, kw) || strings.Contains(rdnsLower, kw) {
			return "cdn"
		}
	}

	// Public DNS resolvers
	publicDNS := []string{"google", "opendns", "quad9", "one.one", "1.1.1.1", "8.8.8.8", "8.8.4.4"}
	for _, kw := range publicDNS {
		if strings.Contains(orgLower, kw) || strings.Contains(rdnsLower, kw) || strings.Contains(info.IP, kw) {
			return "public_resolver"
		}
	}

	// Cloud providers
	cloudKeywords := []string{"amazon", "aws", "azure", "microsoft", "google cloud", "digitalocean", "linode", "vultr", "hetzner", "ovh"}
	for _, kw := range cloudKeywords {
		if strings.Contains(orgLower, kw) || strings.Contains(asnLower, kw) {
			return "cloud"
		}
	}

	// ISP indicators
	ispKeywords := []string{"telecom", "telekom", "comcast", "verizon", "att.net", "virgin", "bt.net", "charter", "cox", "spectrum"}
	for _, kw := range ispKeywords {
		if strings.Contains(orgLower, kw) || strings.Contains(rdnsLower, kw) {
			return "isp"
		}
	}

	// Corporate (has reverse DNS that looks like a company domain)
	if len(info.ReverseDNS) > 0 && !strings.Contains(rdnsLower, "generic") {
		parts := strings.Split(info.ReverseDNS[0], ".")
		if len(parts) >= 2 {
			// Has a real hostname — likely corporate
			return "corporate"
		}
	}

	return "unknown"
}

// Summarize generates a human-readable network path description.
func Summarize(info IPInfo) string {
	parts := []string{}

	if info.Org != "" {
		parts = append(parts, info.Org)
	}
	if info.Class != "" && info.Class != "unknown" {
		parts = append(parts, "("+info.Class+")")
	}
	if info.City != "" && info.Country != "" {
		parts = append(parts, info.City+", "+info.Country)
	} else if info.Country != "" {
		parts = append(parts, info.Country)
	}
	if len(info.ReverseDNS) > 0 {
		parts = append(parts, "["+info.ReverseDNS[0]+"]")
	}

	if len(parts) == 0 {
		return info.IP
	}
	return info.IP + " — " + strings.Join(parts, " ")
}
