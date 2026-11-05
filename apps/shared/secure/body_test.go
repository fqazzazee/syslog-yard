package secure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func limitedMux(ran *bool) http.Handler {
	mux := http.NewServeMux()
	read := func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		if _, err := io.ReadAll(r.Body); err != nil {
			WriteBodyError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("POST /small", read)
	mux.HandleFunc("PUT /big", read)
	mux.HandleFunc("GET /read", read)
	mux.HandleFunc("POST /nobody", func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusNoContent)
	})
	return BodyLimit{Default: 10, Routes: map[string]int64{"PUT /big": 100}}.Wrap(mux)
}

func TestBodyLimit(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		chunked                  bool
		want                     int
		ran                      bool
	}{
		{"default cap fits", "POST", "/small", strings.Repeat("x", 10), false, 204, true},
		{"default cap declared over", "POST", "/small", strings.Repeat("x", 11), false, 413, false},
		{"default cap chunked over", "POST", "/small", strings.Repeat("x", 11), true, 413, true},
		{"override fits", "PUT", "/big", strings.Repeat("x", 100), false, 204, true},
		{"override declared over", "PUT", "/big", strings.Repeat("x", 101), false, 413, false},
		{"override chunked over", "PUT", "/big", strings.Repeat("x", 101), true, 413, true},
		{"bodyless route still capped", "POST", "/nobody", strings.Repeat("x", 11), false, 413, false},
		{"reads are not capped", "GET", "/read", strings.Repeat("x", 11), false, 204, true},
		{"unknown route uses default", "POST", "/nowhere", strings.Repeat("x", 11), false, 413, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ran bool
			h := limitedMux(&ran)
			var body io.Reader = strings.NewReader(c.body)
			if c.chunked {
				body = io.MultiReader(body) // hides the length from NewRequest
			}
			r := httptest.NewRequest(c.method, c.path, body)
			if c.chunked && r.ContentLength != -1 {
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d (%s)", w.Code, c.want, w.Body)
			}
			if ran != c.ran {
				t.Fatalf("handler ran = %v, want %v", ran, c.ran)
			}
			if c.want == http.StatusRequestEntityTooLarge {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !strings.Contains(resp["error"], "larger than") {
					t.Fatalf("413 body %q is not {\"error\": ...}", w.Body)
				}
				if ct := w.Header().Get("Content-Type"); ct != "application/json" {
					t.Fatalf("Content-Type %q", ct)
				}
			}
		})
	}
}

func TestWriteBodyErrorOther(t *testing.T) {
	w := httptest.NewRecorder()
	WriteBodyError(w, io.ErrUnexpectedEOF)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error":"unexpected EOF"`) {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
}
