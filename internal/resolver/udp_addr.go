package resolver

import (
	"context"
	"net"
	"strconv"
	"strings"
)

func resolveUDPAddr(ctx context.Context, server string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port, err = net.LookupPort("udp", portStr)
		if err != nil {
			return nil, err
		}
	}

	// Zoned IPv6 literal (e.g. "fe80::1%en0").
	if zi := strings.LastIndexByte(host, '%'); zi != -1 {
		ipPart := host[:zi]
		zone := host[zi+1:]
		if ip := net.ParseIP(ipPart); ip != nil {
			return &net.UDPAddr{IP: ip, Port: port, Zone: zone}, nil
		}
	}

	// IP literal.
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	// Hostname.
	if ctx == nil {
		ctx = context.Background()
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}
