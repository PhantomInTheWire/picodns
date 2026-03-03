package resolver

import (
	"encoding/binary"

	"picodns/internal/dns"
)

// setRAFlag sets the Recursion Available (RA) flag in a DNS response header.
func setRAFlag(resp []byte) {
	if len(resp) < 4 {
		return
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= dns.FlagRA
	binary.BigEndian.PutUint16(resp[2:4], flags)
}

// setResponseID updates the transaction ID in a DNS message header.
func setResponseID(resp []byte, id uint16) {
	if len(resp) < 2 {
		return
	}
	binary.BigEndian.PutUint16(resp[0:2], id)
}

// minimizeAndSetID minimizes the response and sets the transaction ID.
// This is a helper to avoid duplication since MinimizeResponse calls WriteHeader
// which overwrites the transaction ID.
func minimizeAndSetID(resp []byte, clientID uint16, keepAuthorities bool) ([]byte, error) {
	minimized, err := dns.MinimizeResponse(resp, keepAuthorities)
	if err != nil {
		setResponseID(resp, clientID)
		return resp, err
	}
	setResponseID(minimized, clientID)
	return minimized, nil
}
