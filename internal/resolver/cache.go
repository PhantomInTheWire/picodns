package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"picodns/internal/cache"
	"picodns/internal/dns"
)

// Resolver is the interface for DNS resolution
type Resolver interface {
	Resolve(ctx context.Context, req []byte) ([]byte, error)
}

// dnsCacheEntry stores the semantic data from a DNS response
// without the transaction ID, allowing responses to be cached
// and served to queries with different IDs
type dnsCacheEntry struct {
	Header      dns.Header
	Answers     []dns.ResourceRecord
	Authorities []dns.ResourceRecord
	Additionals []dns.ResourceRecord
	Expires     time.Time
}

// Cached wraps a resolver with DNS response caching
type Cached struct {
	cache    *cache.Cache
	upstream Resolver
}

func NewCached(cacheStore *cache.Cache, upstream Resolver) *Cached {
	return &Cached{cache: cacheStore, upstream: upstream}
}

func (c *Cached) Resolve(ctx context.Context, req []byte) ([]byte, error) {
	reqMsg, err := dns.ReadMessage(req)
	if err != nil || len(reqMsg.Questions) == 0 {
		return c.upstream.Resolve(ctx, req)
	}

	q := reqMsg.Questions[0]

	// Try to get from cache and rebuild response with correct ID
	if cached, ok := c.getCached(q, reqMsg.Header.ID); ok {
		return cached, nil
	}

	resp, err := c.upstream.Resolve(ctx, req)
	if err != nil || dns.ValidateResponse(req, resp) != nil {
		return resp, err
	}

	// Parse and cache the response
	if respMsg, err := dns.ReadMessage(resp); err == nil {
		if ttl, ok := extractTTL(respMsg, q); ok {
			c.setCache(q, respMsg, ttl)
		}
	}
	return resp, nil
}

// getCached retrieves a cached response and rebuilds it with the correct transaction ID
func (c *Cached) getCached(q dns.Question, queryID uint16) ([]byte, bool) {
	if c.cache == nil {
		return nil, false
	}

	// Get the raw cached data
	cachedData, ok := c.cache.Get(q)
	if !ok {
		return nil, false
	}

	// Deserialize the cache entry
	entry, err := deserializeCacheEntry(cachedData)
	if err != nil {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.Expires) {
		return nil, false
	}

	// Rebuild response with the query's transaction ID
	return buildResponseFromCache(entry, q, queryID), true
}

// setCache stores a parsed DNS message in the cache
func (c *Cached) setCache(q dns.Question, msg dns.Message, ttl time.Duration) {
	if c.cache == nil || ttl <= 0 {
		return
	}

	entry := &dnsCacheEntry{
		Header:      msg.Header,
		Answers:     msg.Answers,
		Authorities: msg.Authorities,
		Additionals: msg.Additionals,
		Expires:     time.Now().Add(ttl),
	}

	// Serialize and store
	data := serializeCacheEntry(entry)
	c.cache.Set(q, data, ttl)
}

// serializeCacheEntry converts a cache entry to bytes
func serializeCacheEntry(entry *dnsCacheEntry) []byte {
	// Simple serialization: header counts + all records
	buf := make([]byte, 0, 4096)

	// Store header counts (without ID)
	buf = append(buf, byte(entry.Header.Flags>>8), byte(entry.Header.Flags))
	buf = append(buf, byte(entry.Header.QDCount>>8), byte(entry.Header.QDCount))
	buf = append(buf, byte(entry.Header.ANCount>>8), byte(entry.Header.ANCount))
	buf = append(buf, byte(entry.Header.NSCount>>8), byte(entry.Header.NSCount))
	buf = append(buf, byte(entry.Header.ARCount>>8), byte(entry.Header.ARCount))

	// Store expiry time
	expiryBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiryBytes, uint64(entry.Expires.Unix()))
	buf = append(buf, expiryBytes...)

	// Serialize records
	buf = serializeRecords(buf, entry.Answers)
	buf = serializeRecords(buf, entry.Authorities)
	buf = serializeRecords(buf, entry.Additionals)

	return buf
}

// deserializeCacheEntry converts bytes back to a cache entry
func deserializeCacheEntry(data []byte) (*dnsCacheEntry, error) {
	if len(data) < 18 {
		return nil, errors.New("cache data too short")
	}

	entry := &dnsCacheEntry{}

	// Read header counts
	entry.Header.Flags = binary.BigEndian.Uint16(data[0:2])
	entry.Header.QDCount = binary.BigEndian.Uint16(data[2:4])
	entry.Header.ANCount = binary.BigEndian.Uint16(data[4:6])
	entry.Header.NSCount = binary.BigEndian.Uint16(data[6:8])
	entry.Header.ARCount = binary.BigEndian.Uint16(data[8:10])

	// Read expiry
	entry.Expires = time.Unix(int64(binary.BigEndian.Uint64(data[10:18])), 0)
	off := 18

	// Deserialize records
	var err error
	entry.Answers, off, err = deserializeRecords(data, off, int(entry.Header.ANCount))
	if err != nil {
		return nil, err
	}
	entry.Authorities, off, err = deserializeRecords(data, off, int(entry.Header.NSCount))
	if err != nil {
		return nil, err
	}
	entry.Additionals, off, err = deserializeRecords(data, off, int(entry.Header.ARCount))
	if err != nil {
		return nil, err
	}

	return entry, nil
}

// serializeRecords serializes resource records to bytes
func serializeRecords(buf []byte, records []dns.ResourceRecord) []byte {
	for _, rr := range records {
		// Store name length + name
		nameBytes := []byte(rr.Name)
		buf = append(buf, byte(len(nameBytes)>>8), byte(len(nameBytes)))
		buf = append(buf, nameBytes...)

		// Store type, class, TTL
		buf = append(buf, byte(rr.Type>>8), byte(rr.Type))
		buf = append(buf, byte(rr.Class>>8), byte(rr.Class))
		buf = append(buf, byte(rr.TTL>>24), byte(rr.TTL>>16), byte(rr.TTL>>8), byte(rr.TTL))

		// Store data length + data
		buf = append(buf, byte(len(rr.Data)>>8), byte(len(rr.Data)))
		buf = append(buf, rr.Data...)
	}
	return buf
}

// deserializeRecords deserializes resource records from bytes
func deserializeRecords(data []byte, off int, count int) ([]dns.ResourceRecord, int, error) {
	records := make([]dns.ResourceRecord, 0, count)

	for i := 0; i < count; i++ {
		if off+2 > len(data) {
			return nil, off, errors.New("insufficient data for record")
		}

		nameLen := binary.BigEndian.Uint16(data[off : off+2])
		off += 2

		if off+int(nameLen)+10 > len(data) {
			return nil, off, errors.New("insufficient data for record")
		}

		rr := dns.ResourceRecord{
			Name: string(data[off : off+int(nameLen)]),
		}
		off += int(nameLen)

		rr.Type = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		rr.Class = binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		rr.TTL = binary.BigEndian.Uint32(data[off : off+4])
		off += 4

		dataLen := binary.BigEndian.Uint16(data[off : off+2])
		off += 2

		if off+int(dataLen) > len(data) {
			return nil, off, errors.New("insufficient data for record data")
		}

		rr.Data = make([]byte, dataLen)
		copy(rr.Data, data[off:off+int(dataLen)])
		off += int(dataLen)

		records = append(records, rr)
	}

	return records, off, nil
}

// buildResponseFromCache rebuilds a DNS response from cached data with the correct transaction ID
func buildResponseFromCache(entry *dnsCacheEntry, q dns.Question, queryID uint16) []byte {
	buf := make([]byte, dns.MaxMessageSize)

	// Write header with query's ID
	header := dns.Header{
		ID:      queryID,
		Flags:   entry.Header.Flags | dns.FlagQR | dns.FlagRA, // Response flags
		QDCount: 1,
		ANCount: uint16(len(entry.Answers)),
		NSCount: uint16(len(entry.Authorities)),
		ARCount: uint16(len(entry.Additionals)),
	}
	dns.WriteHeader(buf, header)

	// Write question section
	off := dns.HeaderLen
	off, _ = dns.EncodeName(buf, off, q.Name)
	binary.BigEndian.PutUint16(buf[off:off+2], q.Type)
	binary.BigEndian.PutUint16(buf[off+2:off+4], q.Class)
	off += 4

	// Remember where the question name ends for compression
	qNameEnd := dns.HeaderLen + len(q.Name) + 2 // +2 for root label and type/class
	if q.Name[len(q.Name)-1] == '.' {
		qNameEnd = dns.HeaderLen + len(q.Name) + 1 // +1 for root label
	}

	// Write answer section
	off = writeRecords(buf, off, entry.Answers, qNameEnd, q.Name)

	// Write authority section
	off = writeRecords(buf, off, entry.Authorities, qNameEnd, q.Name)

	// Write additional section
	off = writeRecords(buf, off, entry.Additionals, qNameEnd, q.Name)

	return buf[:off]
}

// writeRecords writes resource records to the buffer
func writeRecords(buf []byte, off int, records []dns.ResourceRecord, qNameEnd int, qName string) int {
	for _, rr := range records {
		// Use compression pointer if the name matches the question
		if rr.Name == qName || rr.Name == qName+"." {
			if off+2 > len(buf) {
				break
			}
			// Compression pointer to question name at offset 12 (HeaderLen)
			buf[off] = 0xC0
			buf[off+1] = 0x0C
			off += 2
		} else {
			// Write full name
			var err error
			off, err = dns.EncodeName(buf, off, rr.Name)
			if err != nil {
				continue
			}
		}

		// Write type, class, TTL
		if off+10 > len(buf) {
			break
		}
		binary.BigEndian.PutUint16(buf[off:off+2], rr.Type)
		binary.BigEndian.PutUint16(buf[off+2:off+4], rr.Class)
		binary.BigEndian.PutUint32(buf[off+4:off+8], rr.TTL)
		binary.BigEndian.PutUint16(buf[off+8:off+10], uint16(len(rr.Data)))
		off += 10

		// Write data
		if off+len(rr.Data) > len(buf) {
			break
		}
		copy(buf[off:off+len(rr.Data)], rr.Data)
		off += len(rr.Data)
	}
	return off
}

func extractTTL(msg dns.Message, q dns.Question) (time.Duration, bool) {
	if (msg.Header.Flags & 0x000F) == dns.RcodeNXDomain {
		for _, rr := range msg.Authorities {
			if rr.Type == dns.TypeSOA && len(rr.Data) >= 20 {
				_, nextM, _ := dns.DecodeName(rr.Data, 0)
				_, nextR, _ := dns.DecodeName(rr.Data, nextM)
				if len(rr.Data) >= nextR+20 {
					return time.Duration(binary.BigEndian.Uint32(rr.Data[nextR+16:nextR+20])) * time.Second, true
				}
			}
		}
		return 0, false
	}

	q = q.Normalize()
	for _, rr := range msg.Answers {
		if rr.Type == q.Type && rr.Class == q.Class && rr.TTL > 0 {
			if rq := (dns.Question{Name: rr.Name, Type: rr.Type, Class: rr.Class}.Normalize()); rq.Name == q.Name {
				return time.Duration(rr.TTL) * time.Second, true
			}
		}
	}
	return 0, false
}
