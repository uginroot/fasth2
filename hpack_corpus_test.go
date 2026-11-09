package fasth2

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestHPACKTestCase decodes the http2jp/hpack-test-case corpus: header blocks
// produced by many independent encoders (nghttp2, Go, node, python, haskell,
// swift-nio). Run with HPACK_TEST_CASE_DIR=/path/to/hpack-test-case.
func TestHPACKTestCase(t *testing.T) {
	dir := os.Getenv("HPACK_TEST_CASE_DIR")
	if dir == "" {
		t.Skip("HPACK_TEST_CASE_DIR not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*", "story_*.json"))
	if len(files) == 0 {
		t.Fatalf("no stories in %s", dir)
	}
	cases := 0
	for _, f := range files {
		if filepath.Base(filepath.Dir(f)) == "raw-data" {
			continue // no wire encodings there
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var story struct {
			Cases []struct {
				Seqno           int                 `json:"seqno"`
				HeaderTableSize *int                `json:"header_table_size"`
				Wire            string              `json:"wire"`
				Headers         []map[string]string `json:"headers"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &story); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		d := newDecoder()
		for _, c := range story.Cases {
			if c.HeaderTableSize != nil && *c.HeaderTableSize > d.allowed {
				d.allowed = *c.HeaderTableSize // what our SETTINGS would have advertised
			}
			wire, err := hex.DecodeString(c.Wire)
			if err != nil {
				t.Fatalf("%s #%d: bad hex", f, c.Seqno)
			}
			var arena []byte
			var fields []HeaderField
			if err := d.decode(wire, &arena, &fields); err != nil {
				t.Fatalf("%s #%d: %v", f, c.Seqno, err)
			}
			if len(fields) != len(c.Headers) {
				t.Fatalf("%s #%d: %d fields, want %d", f, c.Seqno, len(fields), len(c.Headers))
			}
			for i, h := range c.Headers {
				for n, v := range h {
					if string(fields[i].Name) != n || string(fields[i].Value) != v {
						t.Fatalf("%s #%d field %d: got %q=%q want %q=%q",
							f, c.Seqno, i, fields[i].Name, fields[i].Value, n, v)
					}
				}
			}
			cases++
		}
	}
	t.Logf("decoded %d header blocks from %d stories", cases, len(files))
}
