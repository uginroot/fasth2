package fasth2

import "errors"

// headerField is a decoded header. Slices are valid only during the handler call.
type headerField struct {
	Name, Value []byte
}

var errCompression = errors.New("hpack: compression error")

const maxHeaderFields = 1024

type hfEntry struct{ name, value []byte }

var staticTable = [61]hfEntry{
	{[]byte(":authority"), nil}, {[]byte(":method"), []byte("GET")}, {[]byte(":method"), []byte("POST")},
	{[]byte(":path"), []byte("/")}, {[]byte(":path"), []byte("/index.html")}, {[]byte(":scheme"), []byte("http")},
	{[]byte(":scheme"), []byte("https")}, {[]byte(":status"), []byte("200")}, {[]byte(":status"), []byte("204")},
	{[]byte(":status"), []byte("206")}, {[]byte(":status"), []byte("304")}, {[]byte(":status"), []byte("400")},
	{[]byte(":status"), []byte("404")}, {[]byte(":status"), []byte("500")}, {[]byte("accept-charset"), nil},
	{[]byte("accept-encoding"), []byte("gzip, deflate")}, {[]byte("accept-language"), nil}, {[]byte("accept-ranges"), nil},
	{[]byte("accept"), nil}, {[]byte("access-control-allow-origin"), nil}, {[]byte("age"), nil}, {[]byte("allow"), nil},
	{[]byte("authorization"), nil}, {[]byte("cache-control"), nil}, {[]byte("content-disposition"), nil},
	{[]byte("content-encoding"), nil}, {[]byte("content-language"), nil}, {[]byte("content-length"), nil},
	{[]byte("content-location"), nil}, {[]byte("content-range"), nil}, {[]byte("content-type"), nil},
	{[]byte("cookie"), nil}, {[]byte("date"), nil}, {[]byte("etag"), nil}, {[]byte("expect"), nil},
	{[]byte("expires"), nil}, {[]byte("from"), nil}, {[]byte("host"), nil}, {[]byte("if-match"), nil},
	{[]byte("if-modified-since"), nil}, {[]byte("if-none-match"), nil}, {[]byte("if-range"), nil},
	{[]byte("if-unmodified-since"), nil}, {[]byte("last-modified"), nil}, {[]byte("link"), nil},
	{[]byte("location"), nil}, {[]byte("max-forwards"), nil}, {[]byte("proxy-authenticate"), nil},
	{[]byte("proxy-authorization"), nil}, {[]byte("range"), nil}, {[]byte("referer"), nil}, {[]byte("refresh"), nil},
	{[]byte("retry-after"), nil}, {[]byte("server"), nil}, {[]byte("set-cookie"), nil},
	{[]byte("strict-transport-security"), nil}, {[]byte("transfer-encoding"), nil}, {[]byte("user-agent"), nil},
	{[]byte("vary"), nil}, {[]byte("via"), nil}, {[]byte("www-authenticate"), nil},
}

var staticNameIdx = func() map[string]uint64 {
	m := make(map[string]uint64)
	for i := len(staticTable) - 1; i >= 0; i-- {
		m[string(staticTable[i].name)] = uint64(i + 1)
	}
	return m
}()

// hpackDecoder is a per-connection HPACK decoder (RFC 7541).
type hpackDecoder struct {
	dyn     []hfEntry // oldest first
	size    int
	maxSize int
	allowed int // SETTINGS_HEADER_TABLE_SIZE we advertised
}

func newDecoder() hpackDecoder { return hpackDecoder{maxSize: 4096, allowed: 4096} }

func readInt(p []byte, prefix uint) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, p, errCompression
	}
	max := uint64(1)<<prefix - 1
	v := uint64(p[0]) & max
	p = p[1:]
	if v < max {
		return v, p, nil
	}
	var m uint
	for {
		if len(p) == 0 || m > 28 {
			return 0, p, errCompression
		}
		b := p[0]
		p = p[1:]
		v += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			if v > 1<<32 {
				return 0, p, errCompression
			}
			return v, p, nil
		}
		m += 7
	}
}

func (d *hpackDecoder) at(idx uint64) (name, value []byte, ok bool) {
	if idx == 0 {
		return nil, nil, false
	}
	if idx <= uint64(len(staticTable)) {
		e := &staticTable[idx-1]
		return e.name, e.value, true
	}
	i := idx - uint64(len(staticTable)) - 1
	if i >= uint64(len(d.dyn)) {
		return nil, nil, false
	}
	e := &d.dyn[len(d.dyn)-1-int(i)]
	return e.name, e.value, true
}

func (d *hpackDecoder) evict(extra int) {
	k := 0
	for d.size+extra > d.maxSize && k < len(d.dyn) {
		d.size -= len(d.dyn[k].name) + len(d.dyn[k].value) + 32
		k++
	}
	if k > 0 {
		n := copy(d.dyn, d.dyn[k:])
		for i := n; i < len(d.dyn); i++ {
			d.dyn[i] = hfEntry{}
		}
		d.dyn = d.dyn[:n]
	}
}

func (d *hpackDecoder) add(name, value []byte) {
	sz := len(name) + len(value) + 32
	if sz > d.maxSize {
		d.evict(d.maxSize + 1) // clears table
		return
	}
	d.evict(sz)
	b := make([]byte, len(name)+len(value))
	copy(b, name)
	copy(b[len(name):], value)
	d.dyn = append(d.dyn, hfEntry{b[:len(name):len(name)], b[len(name):]})
	d.size += sz
}

func (d *hpackDecoder) readString(p []byte, arena *[]byte) ([]byte, []byte, error) {
	if len(p) == 0 {
		return nil, p, errCompression
	}
	huff := p[0]&0x80 != 0
	l, p, err := readInt(p, 7)
	if err != nil || l > uint64(len(p)) {
		return nil, p, errCompression
	}
	s := p[:l]
	p = p[l:]
	start := len(*arena)
	if huff {
		var err error
		if *arena, err = huffmanDecode(*arena, s); err != nil {
			return nil, p, err
		}
	} else {
		*arena = append(*arena, s...)
	}
	end := len(*arena)
	return (*arena)[start:end:end], p, nil
}

// decode decodes a complete header block, appending fields. Strings are
// copied into arena or point at immutable table entries.
//
// When the decoded header list exceeds maxList bytes (name+value+32 per
// field, RFC 9113 6.5.2) or maxHeaderFields fields, decode keeps decoding
// (the dynamic table must stay in sync with the peer) but stops collecting
// fields and reports tooLarge. An indexed field costs one byte on the wire
// but may expand to a 4 KB table entry, so the limit is on the decoded size.
func (d *hpackDecoder) decode(p []byte, arena *[]byte, fields *[]headerField, maxList int) (tooLarge bool, err error) {
	sawField := false
	size := 0
	for len(p) > 0 {
		b := p[0]
		switch {
		case b&0x80 != 0: // indexed
			idx, rest, err := readInt(p, 7)
			if err != nil {
				return tooLarge, err
			}
			p = rest
			n, v, ok := d.at(idx)
			if !ok {
				return tooLarge, errCompression
			}
			sawField = true
			if !tooLarge {
				size += len(n) + len(v) + 32
				if size > maxList || len(*fields) >= maxHeaderFields {
					tooLarge = true
				} else {
					*fields = append(*fields, headerField{n, v})
				}
			}
		case b&0xe0 == 0x20: // dynamic table size update
			if sawField {
				return tooLarge, errCompression
			}
			sz, rest, err := readInt(p, 5)
			if err != nil || sz > uint64(d.allowed) {
				return tooLarge, errCompression
			}
			p = rest
			d.maxSize = int(sz)
			d.evict(0)
		default: // literal: with incremental indexing (01), without (0000) or never (0001)
			prefix, index := uint(4), false
			if b&0xc0 == 0x40 {
				prefix, index = 6, true
			}
			idx, rest, err := readInt(p, prefix)
			if err != nil {
				return tooLarge, err
			}
			p = rest
			mark := len(*arena)
			var name []byte
			if idx == 0 {
				if name, p, err = d.readString(p, arena); err != nil {
					return tooLarge, err
				}
			} else {
				var ok bool
				if name, _, ok = d.at(idx); !ok {
					return tooLarge, errCompression
				}
			}
			var value []byte
			if value, p, err = d.readString(p, arena); err != nil {
				return tooLarge, err
			}
			if index {
				d.add(name, value) // copies
			}
			sawField = true
			if !tooLarge {
				size += len(name) + len(value) + 32
				if size > maxList || len(*fields) >= maxHeaderFields {
					tooLarge = true
				}
			}
			if tooLarge {
				*arena = (*arena)[:mark] // field is dropped: do not keep its bytes
			} else {
				*fields = append(*fields, headerField{name, value})
			}
		}
	}
	return tooLarge, nil
}

// ---- encoder helpers (stateless: never inserts into the peer's dynamic table) ----

func appendHpackInt(dst []byte, first byte, prefix uint, v uint64) []byte {
	max := uint64(1)<<prefix - 1
	if v < max {
		return append(dst, first|byte(v))
	}
	dst = append(dst, first|byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(v&0x7f)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func appendHpackString(dst []byte, s string) []byte {
	dst = appendHpackInt(dst, 0, 7, uint64(len(s)))
	return append(dst, s...)
}

func appendUintString(dst []byte, v uint64) []byte {
	var tmp [20]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	dst = appendHpackInt(dst, 0, 7, uint64(len(tmp)-i))
	return append(dst, tmp[i:]...)
}

func appendStatus(dst []byte, code int) []byte {
	switch code {
	case 200:
		return append(dst, 0x80|8)
	case 204:
		return append(dst, 0x80|9)
	case 206:
		return append(dst, 0x80|10)
	case 304:
		return append(dst, 0x80|11)
	case 400:
		return append(dst, 0x80|12)
	case 404:
		return append(dst, 0x80|13)
	case 500:
		return append(dst, 0x80|14)
	}
	dst = appendHpackInt(dst, 0x00, 4, 8) // literal without indexing, name = :status
	return appendUintString(dst, uint64(code))
}

func appendLiteral(dst []byte, name, value string) []byte {
	if idx, ok := staticNameIdx[name]; ok {
		dst = appendHpackInt(dst, 0x00, 4, idx)
	} else {
		dst = append(dst, 0x00)
		dst = appendHpackString(dst, name)
	}
	return appendHpackString(dst, value)
}
