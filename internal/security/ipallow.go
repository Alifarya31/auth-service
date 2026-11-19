package security

import (
	"fmt"
	"net/netip"
	"strings"
)

// IPAllowlist berisi daftar IP/CIDR yang diizinkan. Daftar kosong berarti
// semua IP diizinkan (fitur whitelist nonaktif).
type IPAllowlist struct {
	prefixes []netip.Prefix
}

// ParseIPAllowlist menerima entri seperti "127.0.0.1", "10.0.0.0/8", "::1".
func ParseIPAllowlist(entries []string) (*IPAllowlist, error) {
	a := &IPAllowlist{}
	for _, e := range entries {
		if !strings.Contains(e, "/") {
			addr, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("IP_WHITELIST: %q bukan IP valid", e)
			}
			a.prefixes = append(a.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("IP_WHITELIST: %q bukan CIDR valid", e)
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return a, nil
}

func (a *IPAllowlist) Enabled() bool { return a != nil && len(a.prefixes) > 0 }

func (a *IPAllowlist) Allowed(ip string) bool {
	if !a.Enabled() {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap() // "::ffff:127.0.0.1" -> "127.0.0.1"
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
