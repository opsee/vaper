package vaper

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/dvsekhvalnov/jose2go"
	log "github.com/sirupsen/logrus"
)

const (
	AllowDefaultCryptOpts = true
	DefaultAlgorithm      = jose.A128GCMKW
	DefaultEncryption     = jose.A128GCM
)

const TokenTag = "token"

var (
	DefaultKey       = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	defaultCryptOpts = &CryptOpts{DefaultAlgorithm, DefaultEncryption, DefaultKey}
)

type CryptOpts struct {
	Algorithm  string
	Encryption string
	Key        []byte
}

func (c *CryptOpts) Validate() error {
	var missing []string
	if c.Algorithm == "" {
		missing = append(missing, "Algorithm")
	}
	if c.Encryption == "" {
		missing = append(missing, "Encryption")
	}
	if len(c.Key) == 0 {
		missing = append(missing, "Key")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s", strings.Join(missing[:], ","))
	}
	return nil
}

// Creates an encrypted json web token of interface v
func MarshalToken(v interface{}, c *CryptOpts) ([]byte, error) {
	//log.SetLevel(log.DebugLevel)

	e := &encodeState{}
	err := e.marshal(v, encOpts{}) // encOpts is encoding options
	if err != nil {
		return nil, err
	}

	if c == nil {
		if !AllowDefaultCryptOpts {
			return nil, fmt.Errorf("encryption options not specified")
		}
		log.Warn("encryption options not provided, using defaults!")
		c = defaultCryptOpts
	} else {
		if verr := c.Validate(); verr != nil {
			return nil, verr
		}
	}

	s, err := jose.Encrypt(string(e.Bytes()), c.Algorithm, c.Encryption, c.Key)
	return []byte(s), err
}

type TokenMarshaler interface {
	MarshalToken() ([]byte, error)
}

type TokenMarshalerError struct {
	Type reflect.Type
	Err  error
}

func (e *TokenMarshalerError) Error() string {
	return "json: error calling MarshalToken for type " + e.Type.String() + ": " + e.Err.Error()
}

var hex = "0123456789abcdef"

// An encodeState encodes JSON into a bytes.Buffer.
type encodeState struct {
	bytes.Buffer // accumulated output
	scratch      [64]byte
}

var encodeStatePool sync.Pool

func newEncodeState() *encodeState {
	if v := encodeStatePool.Get(); v != nil {
		e := v.(*encodeState)
		e.Reset()
		return e
	}
	return new(encodeState)
}

func (e *encodeState) marshal(v interface{}, opts encOpts) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if s, ok := r.(string); ok {
				panic(s)
			}
			err = r.(error)
		}
	}()
	e.reflectValue(reflect.ValueOf(v), opts)
	return nil
}

func (e *encodeState) error(err error) {
	panic(err)
}

func (e *encodeState) reflectValue(v reflect.Value, opts encOpts) {
	valueEncoder(v)(e, v, opts)
}

func valueEncoder(v reflect.Value) encoderFunc {
	if !v.IsValid() {
		return invalidValueEncoder
	}
	return typeEncoder(v.Type())
}

type UnsupportedTokenTypeError struct {
	Type reflect.Type
}

func (e *UnsupportedTokenTypeError) Error() string {
	return "jwt: unsupported type: " + e.Type.String()
}

type UnsupportedTokenValueError struct {
	Value reflect.Value
	Str   string
}

func (e *UnsupportedTokenValueError) Error() string {
	return "token: unsupported value: " + e.Str
}

func unsupportedTokenTypeEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.error(&UnsupportedTokenTypeError{v.Type()})
}

func invalidValueEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.WriteString("null")
}

type encOpts struct {
	quoted     bool
	escapeHTML bool
}

type encoderFunc func(e *encodeState, v reflect.Value, opts encOpts)

type byName []field

func (x byName) Len() int { return len(x) }

func (x byName) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

func (x byName) Less(i, j int) bool {
	if x[i].name != x[j].name {
		return x[i].name < x[j].name
	}
	if len(x[i].index) != len(x[j].index) {
		return len(x[i].index) < len(x[j].index)
	}
	if x[i].tag != x[j].tag {
		return x[i].tag
	}
	return byIndex(x).Less(i, j)
}

var encoderCache struct {
	sync.RWMutex
	m map[reflect.Type]encoderFunc
}

var (
	marshalerType     = reflect.TypeOf(new(TokenMarshaler)).Elem()
	textMarshalerType = reflect.TypeOf(new(encoding.TextMarshaler)).Elem()
)

func typeEncoder(t reflect.Type) encoderFunc {
	return newTypeEncoder(t, false)
}

// newTypeEncoder constructs an encoderFunc for a type.
// The returned encoder only checks CanAddr when allowAddr is true.
func newTypeEncoder(t reflect.Type, allowAddr bool) encoderFunc {
	log.Debugf("encoding %v of type %T", t, t)
	if t.Implements(marshalerType) {
		return tokenMarshalerEncoder
	}

	if t.Kind() != reflect.Ptr && allowAddr {
		if reflect.PtrTo(t).Implements(marshalerType) {
			return tokenMarshalerEncoder
		}
	}

	if t.Implements(textMarshalerType) {
		return jsonEncoder
	}

	if t.Kind() != reflect.Ptr && allowAddr {
		if reflect.PtrTo(t).Implements(textMarshalerType) {
			return jsonEncoder
		}
	}

	switch t.Kind() {
	case reflect.Ptr:
		return newPtrEncoder(t)
	case reflect.Struct:
		return newStructEncoder(t)
	case reflect.Interface:
		return interfaceEncoder
	case reflect.Map:
		return newMapEncoder(t)
	default:
		return jsonEncoder
	}
}

type ptrEncoder struct {
	elemEnc encoderFunc
}

func interfaceEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	e.reflectValue(v.Elem(), opts)
}

func (pe *ptrEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	pe.elemEnc(e, v.Elem(), opts)
}

func newPtrEncoder(t reflect.Type) encoderFunc {
	enc := &ptrEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

type mapEncoder struct {
	elemEnc encoderFunc
}

func (me *mapEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	e.WriteByte('{')

	// Extract and sort the keys.
	keys := v.MapKeys()
	sv := make([]reflectWithString, len(keys))
	for i, v := range keys {
		sv[i].v = v
		if err := sv[i].resolve(); err != nil {
			e.error(&TokenMarshalerError{v.Type(), err})
		}
	}
	sort.Sort(byString(sv))

	for i, kv := range sv {
		if i > 0 {
			e.WriteByte(',')
		}
		e.string(kv.s, opts.escapeHTML)
		e.WriteByte(':')
		me.elemEnc(e, v.MapIndex(kv.v), opts)
	}
	e.WriteByte('}')
}

func newMapEncoder(t reflect.Type) encoderFunc {
	switch t.Key().Kind() {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	default:
		if !t.Key().Implements(textMarshalerType) {
			return unsupportedTokenTypeEncoder
		}
	}
	me := &mapEncoder{typeEncoder(t.Elem())}
	return me.encode
}

// Encoder for types that implement TokenMarshaler
func tokenMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Kind() == reflect.Ptr && v.IsNil() {
		e.WriteString("null")
		return
	}
	m := v.Interface().(TokenMarshaler)
	b, err := m.MarshalToken()
	if err == nil {
		// copy JSON into buffer, checking validity.
		err = json.Compact(&e.Buffer, b)
	}
	if err != nil {
		e.error(&TokenMarshalerError{v.Type(), err})
	}
}

// Encoder for types included in token that do not implement TokenMarshaler
func jsonEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Kind() == reflect.Ptr && v.IsNil() {
		e.WriteString("null")
		return
	}
	b, err := json.Marshal(v.Interface())
	if err == nil {
		err = json.Compact(&e.Buffer, b)
	}
}

// A field represents a single field found in a struct.
type field struct {
	name      string
	nameBytes []byte                 // []byte(name)
	equalFold func(s, t []byte) bool // bytes.EqualFold or equivalent

	structTag reflect.StructTag
	tag       bool
	index     []int
	typ       reflect.Type
	omitEmpty bool
	quoted    bool
}

func fillField(f field) field {
	f.nameBytes = []byte(f.name)
	f.equalFold = foldFunc(f.nameBytes)
	return f
}

type structEncoder struct {
	fields    []field
	fieldEncs []encoderFunc
}

func (se *structEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	e.WriteByte('{')
	first := true
	for i, f := range se.fields {
		fv := fieldByIndex(v, f.index)

		// if the token tag is blank, don't encode it
		if !fv.IsValid() || f.omitEmpty && isEmptyValue(fv) {
			continue
		}

		if first {
			first = false
		} else {
			e.WriteByte(',')
		}

		e.string(f.name, opts.escapeHTML)
		e.WriteByte(':')
		opts.quoted = f.quoted
		se.fieldEncs[i](e, fv, opts)
	}
	e.WriteByte('}')
}

// typeFields returns a list of fields that JSON should recognize for the given type.
// The algorithm is breadth-first search over the set of structs to include - the top struct
// and then any reachable anonymous structs.
func typeFields(t reflect.Type) []field {
	// Anonymous fields to explore at the current level and the next.
	current := []field{}
	next := []field{{typ: t}}

	// Count of queued names for current level and the next.
	count := map[reflect.Type]int{}
	nextCount := map[reflect.Type]int{}

	// Types already visited at an earlier level.
	visited := map[reflect.Type]bool{}

	// Fields found.
	var fields []field

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true

			// Scan f.typ for fields to include.
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				if sf.PkgPath != "" && !sf.Anonymous { // unexported
					continue
				}
				tag := sf.Tag.Get("token")
				if tag == "-" || tag == "" {
					continue
				}

				name, opts := parseTag(tag)
				if !isValidTag(name) {
					name = ""
				}
				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				if ft.Name() == "" && ft.Kind() == reflect.Ptr {
					// Follow pointer.
					ft = ft.Elem()
				}

				// Only strings, floats, integers, and booleans can be quoted.
				quoted := false
				if opts.Contains("string") {
					switch ft.Kind() {
					case reflect.Bool,
						reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
						reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
						reflect.Float32, reflect.Float64,
						reflect.String:
						quoted = true
					}
				}

				// Record found field and index sequence.
				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					tagged := name != ""
					if name == "" {
						name = sf.Name
					}
					fields = append(fields, fillField(field{
						name:      name,
						tag:       tagged,
						index:     index,
						typ:       ft,
						omitEmpty: opts.Contains("omitempty"),
						quoted:    quoted,
					}))
					if count[f.typ] > 1 {
						// If there were multiple instances, add a second,
						// so that the annihilation code will see a duplicate.
						// It only cares about the distinction between 1 or 2,
						// so don't bother generating any more copies.
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				// Record new anonymous struct to explore in next round.
				nextCount[ft]++
				if nextCount[ft] == 1 {
					next = append(next, fillField(field{name: ft.Name(), index: index, typ: ft}))
				}
			}
		}
	}

	sort.Sort(byName(fields))

	// Delete all fields that are hidden by the Go rules for embedded fields,
	// except that fields with JSON tags are promoted.

	// The fields are sorted in primary order of name, secondary order
	// of field index length. Loop over names; for each name, delete
	// hidden fields by choosing the one dominant field that survives.
	out := fields[:0]
	for advance, i := 0, 0; i < len(fields); i += advance {
		// One iteration per name.
		// Find the sequence of fields with the name of this first field.
		fi := fields[i]
		name := fi.name
		for advance = 1; i+advance < len(fields); advance++ {
			fj := fields[i+advance]
			if fj.name != name {
				break
			}
		}
		if advance == 1 { // Only one field with this name
			out = append(out, fi)
			continue
		}
		dominant, ok := dominantField(fields[i : i+advance])
		if ok {
			out = append(out, dominant)
		}
	}

	fields = out
	sort.Sort(byIndex(fields))

	return fields
}

// dominantField looks through the fields, all of which are known to
// have the same name, to find the single field that dominates the
// others using Go's embedding rules, modified by the presence of
// JSON tags. If there are multiple top-level fields, the boolean
// will be false: This condition is an error in Go and we skip all
// the fields.
func dominantField(fields []field) (field, bool) {
	// The fields are sorted in increasing index-length order. The winner
	// must therefore be one with the shortest index length. Drop all
	// longer entries, which is easy: just truncate the slice.
	length := len(fields[0].index)
	tagged := -1 // Index of first tagged field.
	for i, f := range fields {
		if len(f.index) > length {
			fields = fields[:i]
			break
		}
		if f.tag {
			if tagged >= 0 {
				// Multiple tagged fields at the same level: conflict.
				// Return no field.
				return field{}, false
			}
			tagged = i
		}
	}
	if tagged >= 0 {
		return fields[tagged], true
	}
	// All remaining fields have the same length. If there's more than one,
	// we have a conflict (two fields named "X" at the same level) and we
	// return no field.
	if len(fields) > 1 {
		return field{}, false
	}
	return fields[0], true
}

func newStructEncoder(t reflect.Type) encoderFunc {
	fields := typeFields(t)
	se := &structEncoder{
		fields:    fields,
		fieldEncs: make([]encoderFunc, len(fields)),
	}
	for i, f := range fields {
		se.fieldEncs[i] = typeEncoder(typeByIndex(t, f.index))
	}
	return se.encode
}

func typeByIndex(t reflect.Type, index []int) reflect.Type {
	for _, i := range index {
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		t = t.Field(i).Type
	}
	return t
}

func fieldByIndex(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		default:
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				return false
			}
		}
	}
	return true
}

// NOTE: keep in sync with stringBytes below.
func (e *encodeState) string(s string, escapeHTML bool) int {
	len0 := e.Len()
	e.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if 0x20 <= b && b != '\\' && b != '"' &&
				(!escapeHTML || b != '<' && b != '>' && b != '&') {
				i++
				continue
			}
			if start < i {
				e.WriteString(s[start:i])
			}
			switch b {
			case '\\', '"':
				e.WriteByte('\\')
				e.WriteByte(b)
			case '\n':
				e.WriteByte('\\')
				e.WriteByte('n')
			case '\r':
				e.WriteByte('\\')
				e.WriteByte('r')
			case '\t':
				e.WriteByte('\\')
				e.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				e.WriteString(`\u00`)
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.WriteString(s[start:])
	}
	e.WriteByte('"')
	return e.Len() - len0
}

func (e *encodeState) stringBytes(s []byte, escapeHTML bool) int {
	len0 := e.Len()
	e.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if 0x20 <= b && b != '\\' && b != '"' &&
				(!escapeHTML || b != '<' && b != '>' && b != '&') {
				i++
				continue
			}
			if start < i {
				e.Write(s[start:i])
			}
			switch b {
			case '\\', '"':
				e.WriteByte('\\')
				e.WriteByte(b)
			case '\n':
				e.WriteByte('\\')
				e.WriteByte('n')
			case '\r':
				e.WriteByte('\\')
				e.WriteByte('r')
			case '\t':
				e.WriteByte('\\')
				e.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				e.WriteString(`\u00`)
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRune(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.Write(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.Write(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.Write(s[start:])
	}
	e.WriteByte('"')
	return e.Len() - len0
}

// byIndex sorts field by index sequence.
type byIndex []field

func (x byIndex) Len() int { return len(x) }

func (x byIndex) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

func (x byIndex) Less(i, j int) bool {
	for k, xik := range x[i].index {
		if k >= len(x[j].index) {
			return false
		}
		if xik != x[j].index[k] {
			return xik < x[j].index[k]
		}
	}
	return len(x[i].index) < len(x[j].index)
}

// byString is a slice of reflectWithString where the reflect.Value is either
// a string or an encoding.TextMarshaler.
// It implements the methods to sort by string.
type byString []reflectWithString

func (sv byString) Len() int           { return len(sv) }
func (sv byString) Swap(i, j int)      { sv[i], sv[j] = sv[j], sv[i] }
func (sv byString) Less(i, j int) bool { return sv[i].s < sv[j].s }

type reflectWithString struct {
	v reflect.Value
	s string
}

func (w *reflectWithString) resolve() error {
	log.Debugf("resolve: %v", w)
	if w.v.Kind() == reflect.String {
		w.s = w.v.String()
		return nil
	}
	if tm, ok := w.v.Interface().(encoding.TextMarshaler); ok {
		buf, err := tm.MarshalText()
		w.s = string(buf)
		return err
	}
	switch w.v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.s = strconv.FormatInt(w.v.Int(), 10)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.s = strconv.FormatUint(w.v.Uint(), 10)
		return nil
	}
	panic("unexpected map key type")
}
