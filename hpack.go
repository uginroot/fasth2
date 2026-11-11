package fasth2

import "errors"

// headerField is a decoded header. Slices are valid only during the handler call.
type headerField struct {
	Name, Value []byte
	// key и sval — готовые строки (каноническое имя для net/http и значение),
	// если поле пришло из таблицы HPACK: адаптер берёт их без аллокации. Пусто —
	// строку нужно сделать из Name/Value.
	key, sval string
}

var errCompression = errors.New("hpack: compression error")

const maxHeaderFields = 1024

// hfEntry — запись таблицы HPACK. key и sval создаются один раз при вставке
// (только читатель соединения) и дальше только читаются: клиент шлёт
// повторные поля (user-agent, :authority, заголовки gRPC) индексом, и адаптер
// не делает новую строку на каждый запрос.
type hfEntry struct {
	name, value []byte
	key, sval   string
}

func newEntry(name, value []byte) hfEntry {
	e := hfEntry{name: name, value: value, sval: string(value)}
	if len(name) > 0 && name[0] != ':' {
		e.key = canonicalKey(name)
	}
	return e
}

func init() {
	for i := range staticTable {
		staticTable[i] = newEntry(staticTable[i].name, staticTable[i].value)
	}
}

var staticTable = [61]hfEntry{
	{name: []byte(":authority"), value: nil}, {name: []byte(":method"), value: []byte("GET")}, {name: []byte(":method"), value: []byte("POST")},
	{name: []byte(":path"), value: []byte("/")}, {name: []byte(":path"), value: []byte("/index.html")}, {name: []byte(":scheme"), value: []byte("http")},
	{name: []byte(":scheme"), value: []byte("https")}, {name: []byte(":status"), value: []byte("200")}, {name: []byte(":status"), value: []byte("204")},
	{name: []byte(":status"), value: []byte("206")}, {name: []byte(":status"), value: []byte("304")}, {name: []byte(":status"), value: []byte("400")},
	{name: []byte(":status"), value: []byte("404")}, {name: []byte(":status"), value: []byte("500")}, {name: []byte("accept-charset"), value: nil},
	{name: []byte("accept-encoding"), value: []byte("gzip, deflate")}, {name: []byte("accept-language"), value: nil}, {name: []byte("accept-ranges"), value: nil},
	{name: []byte("accept"), value: nil}, {name: []byte("access-control-allow-origin"), value: nil}, {name: []byte("age"), value: nil}, {name: []byte("allow"), value: nil},
	{name: []byte("authorization"), value: nil}, {name: []byte("cache-control"), value: nil}, {name: []byte("content-disposition"), value: nil},
	{name: []byte("content-encoding"), value: nil}, {name: []byte("content-language"), value: nil}, {name: []byte("content-length"), value: nil},
	{name: []byte("content-location"), value: nil}, {name: []byte("content-range"), value: nil}, {name: []byte("content-type"), value: nil},
	{name: []byte("cookie"), value: nil}, {name: []byte("date"), value: nil}, {name: []byte("etag"), value: nil}, {name: []byte("expect"), value: nil},
	{name: []byte("expires"), value: nil}, {name: []byte("from"), value: nil}, {name: []byte("host"), value: nil}, {name: []byte("if-match"), value: nil},
	{name: []byte("if-modified-since"), value: nil}, {name: []byte("if-none-match"), value: nil}, {name: []byte("if-range"), value: nil},
	{name: []byte("if-unmodified-since"), value: nil}, {name: []byte("last-modified"), value: nil}, {name: []byte("link"), value: nil},
	{name: []byte("location"), value: nil}, {name: []byte("max-forwards"), value: nil}, {name: []byte("proxy-authenticate"), value: nil},
	{name: []byte("proxy-authorization"), value: nil}, {name: []byte("range"), value: nil}, {name: []byte("referer"), value: nil}, {name: []byte("refresh"), value: nil},
	{name: []byte("retry-after"), value: nil}, {name: []byte("server"), value: nil}, {name: []byte("set-cookie"), value: nil},
	{name: []byte("strict-transport-security"), value: nil}, {name: []byte("transfer-encoding"), value: nil}, {name: []byte("user-agent"), value: nil},
	{name: []byte("vary"), value: nil}, {name: []byte("via"), value: nil}, {name: []byte("www-authenticate"), value: nil},
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

func (d *hpackDecoder) at(idx uint64) *hfEntry {
	if idx == 0 {
		return nil
	}
	if idx <= uint64(len(staticTable)) {
		return &staticTable[idx-1]
	}
	i := idx - uint64(len(staticTable)) - 1
	if i >= uint64(len(d.dyn)) {
		return nil
	}
	return &d.dyn[len(d.dyn)-1-int(i)]
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

// add вставляет запись в таблицу (копирует name и value). false — запись больше
// таблицы: таблица очищена, запись не вставлена (RFC 7541 4.4).
func (d *hpackDecoder) add(name, value []byte) bool {
	sz := len(name) + len(value) + 32
	if sz > d.maxSize {
		d.evict(d.maxSize + 1) // clears table
		return false
	}
	d.evict(sz)
	b := make([]byte, len(name)+len(value))
	copy(b, name)
	copy(b[len(name):], value)
	d.dyn = append(d.dyn, newEntry(b[:len(name):len(name)], b[len(name):]))
	d.size += sz
	return true
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
			e := d.at(idx)
			if e == nil {
				return tooLarge, errCompression
			}
			sawField = true
			if !tooLarge {
				size += len(e.name) + len(e.value) + 32
				if size > maxList || len(*fields) >= maxHeaderFields {
					tooLarge = true
				} else {
					*fields = append(*fields, headerField{e.name, e.value, e.key, e.sval})
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
			var key, sval string
			if idx == 0 {
				if name, p, err = d.readString(p, arena); err != nil {
					return tooLarge, err
				}
			} else {
				e := d.at(idx)
				if e == nil {
					return tooLarge, errCompression
				}
				name, key = e.name, e.key
			}
			var value []byte
			if value, p, err = d.readString(p, arena); err != nil {
				return tooLarge, err
			}
			if index && d.add(name, value) { // add копирует
				e := &d.dyn[len(d.dyn)-1] // только что вставленная запись: её строки
				key, sval = e.key, e.sval
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
				*fields = append(*fields, headerField{name, value, key, sval})
			}
		}
	}
	return tooLarge, nil
}

// ---- encoder helpers ----

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

// ---- encoder with a dynamic table (responses) ----

// hpField — поле заголовка ответа: имя в нижнем регистре, значение проверено
// адаптером (validFieldName, validFieldValue).
type hpField struct{ name, value string }

type encKey struct{ name, value string }

type encEntry struct {
	name, value string
	n           uint64 // номер вставки
}

// encMaxTable — размер динамической таблицы кодера (по умолчанию в HTTP/2).
const encMaxTable = 4096

// hpackEncoder кодирует заголовки ответов с динамической таблицей (RFC 7541):
// повторный content-type, date, grpc-status и т. п. занимают 1 байт вместо
// 10–30. Один кодер на соединение; вызывается под c.mu в том порядке, в каком
// блоки уходят в c.wbuf: каждый закодированный блок должен дойти до клиента,
// иначе таблицы кодера и декодера разойдутся.
type hpackEncoder struct {
	ents    []encEntry // старые первыми
	size    int
	maxSize int
	update  bool // в начале следующего блока нужно обновление размера таблицы
	inserts uint64
	byField map[encKey]uint64 // поле → номер вставки
	byName  map[string]uint64 // имя → номер вставки
}

func newEncoder() hpackEncoder {
	return hpackEncoder{maxSize: encMaxTable, byField: make(map[encKey]uint64), byName: make(map[string]uint64)}
}

// setLimit применяет SETTINGS_HEADER_TABLE_SIZE клиента. Как x/net: таблица
// только уменьшается, а уменьшение объявляется в начале следующего блока.
// Последний размер — всегда наименьший, поэтому хватает одного обновления.
func (e *hpackEncoder) setLimit(v uint32) {
	if int64(v) >= int64(e.maxSize) {
		return
	}
	e.maxSize = int(v)
	e.update = true
	e.evict(0)
}

// begin начинает блок заголовков: при необходимости — обновление размера таблицы.
func (e *hpackEncoder) begin(dst []byte) []byte {
	if !e.update {
		return dst
	}
	e.update = false
	return appendHpackInt(dst, 0x20, 5, uint64(e.maxSize))
}

func (e *hpackEncoder) index(n uint64) uint64 { return 62 + (e.inserts - 1 - n) }

// encode добавляет поле: индекс, если поле уже в таблице; иначе литерал с
// индексированием. Не индексируются set-cookie (never indexed, RFC 7541 7.1.3)
// и большие значения (не вытесняют полезные записи).
func (e *hpackEncoder) encode(dst []byte, name, value string) []byte {
	if n, ok := e.byField[encKey{name, value}]; ok {
		return appendHpackInt(dst, 0x80, 7, e.index(n))
	}
	nameIdx, ok := staticNameIdx[name]
	if !ok {
		if n, ok := e.byName[name]; ok {
			nameIdx = e.index(n)
		}
	}
	size := len(name) + len(value) + 32
	switch {
	case name == "set-cookie":
		dst = appendLiteralName(dst, 0x10, 4, nameIdx, name) // never indexed
	case size <= e.maxSize/4:
		dst = appendLiteralName(dst, 0x40, 6, nameIdx, name)
		e.add(name, value, size)
	default:
		dst = appendLiteralName(dst, 0x00, 4, nameIdx, name)
	}
	return appendHpackString(dst, value)
}

func appendLiteralName(dst []byte, first byte, prefix uint, nameIdx uint64, name string) []byte {
	if nameIdx > 0 {
		return appendHpackInt(dst, first, prefix, nameIdx)
	}
	dst = append(dst, first)
	return appendHpackString(dst, name)
}

func (e *hpackEncoder) add(name, value string, size int) {
	e.evict(size)
	n := e.inserts
	e.inserts++
	e.ents = append(e.ents, encEntry{name, value, n})
	e.size += size
	e.byField[encKey{name, value}] = n
	e.byName[name] = n
}

// evict освобождает место под запись размера extra.
func (e *hpackEncoder) evict(extra int) {
	k := 0
	for k < len(e.ents) && e.size+extra > e.maxSize {
		old := &e.ents[k]
		e.size -= len(old.name) + len(old.value) + 32
		if e.byField[encKey{old.name, old.value}] == old.n {
			delete(e.byField, encKey{old.name, old.value})
		}
		if e.byName[old.name] == old.n {
			delete(e.byName, old.name)
		}
		k++
	}
	if k > 0 {
		e.ents = append(e.ents[:0], e.ents[k:]...)
	}
}
