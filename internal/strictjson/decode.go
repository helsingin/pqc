// Package strictjson rejects duplicate members and ambiguous object shapes.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Decode requires exact JSON field names, rejects unknown/duplicate members and
// trailing values, and optionally requires every non-omitempty struct field.
func Decode(data []byte, value any, required bool) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8 JSON")
	}
	if err := surrogates(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walk(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	typ := reflect.TypeOf(value)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return fmt.Errorf("JSON target must be a pointer")
	}
	if err := shape(data, typ.Elem(), required); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// Reject lone UTF-16 surrogates rather than accepting encoding/json replacement.
func surrogates(data []byte) error {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
			continue
		}
		if i+1 >= len(data) {
			break
		}
		if data[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(data) {
			break
		}
		value, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return err
		}
		if value >= 0xdc00 && value <= 0xdfff {
			return fmt.Errorf("unpaired low surrogate")
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+12 > len(data) || string(data[i+6:i+8]) != `\u` {
				return fmt.Errorf("unpaired high surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("invalid surrogate pair")
			}
			i += 11
		} else {
			i += 5
		}
	}
	return nil
}

func walk(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting exceeds 32")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid JSON member %v", token)
			}
			seen[name] = true
			if err := walk(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walk(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func shape(data []byte, typ reflect.Type, required bool) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		if typ.Kind() == reflect.Slice {
			return nil
		}
		return fmt.Errorf("null is not valid for %s", typ)
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		expected := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if field.PkgPath != "" || tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			expected[name] = true
			raw, present := fields[name]
			if !present {
				optional := false
				for _, option := range tag[1:] {
					optional = optional || option == "omitempty"
				}
				if required && !optional {
					return fmt.Errorf("missing JSON field %q", name)
				}
				continue
			}
			if err := shape(raw, field.Type, required); err != nil {
				return fmt.Errorf("field %s: %w", name, err)
			}
		}
		for name := range fields {
			if !expected[name] {
				return fmt.Errorf("unknown JSON field %q", name)
			}
		}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, raw := range values {
			if err := shape(raw, typ.Elem(), required); err != nil {
				return err
			}
		}
	}
	return nil
}
