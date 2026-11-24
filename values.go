package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Values are the values of an attribute in a configuration: a list, or a single text or
// number for one value (mail: jdoe@example.com).
type Values []string

// UnmarshalJSON accepts a list or a single value.
func (v *Values) UnmarshalJSON(data []byte) error {
	var list []any
	if err := json.Unmarshal(data, &list); err != nil {
		var one any
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		if one == nil {
			*v = nil
			return nil
		}
		list = []any{one}
	}
	out := make(Values, 0, len(list))
	for _, item := range list {
		switch x := item.(type) {
		case string:
			out = append(out, x)
		case float64:
			out = append(out, strconv.FormatFloat(x, 'f', -1, 64))
		case bool:
			out = append(out, strconv.FormatBool(x))
		default:
			return fmt.Errorf("a value of an attribute must be a text or number, not %s", string(data))
		}
	}
	*v = out
	return nil
}

// sortedKeys returns the attribute names in a fixed order, so that requests are reproducible.
func sortedKeys(m map[string]Values) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeValues turns the raw values of an attribute into texts: GUIDs and SIDs of Active
// Directory in their usual notation, other values as text if they are UTF-8, else Base64.
func decodeValues(name string, raw [][]byte) []string {
	out := make([]string, 0, len(raw))
	for _, b := range raw {
		out = append(out, decodeValue(name, b))
	}
	return out
}

func decodeValue(name string, b []byte) string {
	switch strings.ToLower(name) {
	case "objectguid", "msexchmailboxguid", "msds-consistencyguid":
		if len(b) == 16 {
			return guidString(b)
		}
	case "objectsid", "sidhistory", "tokengroups", "securityidentifier", "msds-creatorsid":
		if s, ok := sidString(b); ok {
			return s
		}
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// guidString writes a GUID as Active Directory stores it (first three parts little-endian).
func guidString(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// sidString writes a security identifier as S-1-5-21-….
func sidString(b []byte) (string, bool) {
	if len(b) < 8 || b[0] != 1 {
		return "", false
	}
	count := int(b[1])
	if len(b) != 8+4*count {
		return "", false
	}
	var authority uint64
	for _, x := range b[2:8] {
		authority = authority<<8 | uint64(x)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", b[0], authority)
	for i := range count {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), true
}
