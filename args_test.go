package main

import (
	"strings"
	"testing"
)

func TestRequiredString(t *testing.T) {
	req := newRequest("t", map[string]any{"present": "value", "empty": ""})

	got, err := requiredString(req, "present", 1024)
	if err != nil || got != "value" {
		t.Fatalf("requiredString = %q, %v", got, err)
	}

	for _, name := range []string{"empty", "absent"} {
		if _, err := requiredString(req, name, 1024); err == nil {
			t.Errorf("requiredString(%q) accepted a missing value", name)
		} else if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the argument", err)
		}
	}

	if _, err := requiredString(req, "present", 2); err == nil {
		t.Error("the size limit was not enforced")
	}
}

func TestOptionalJSON(t *testing.T) {
	req := newRequest("t", map[string]any{
		"obj":     `{"a":1}`,
		"arr":     `[1,2]`,
		"broken":  `{`,
		"empty":   "",
		"scalar":  `7`,
		"tooLong": strings.Repeat("x", 100),
	})

	var obj map[string]any
	ok, err := optionalJSON(req, "obj", 1024, &obj)
	if err != nil || !ok || obj["a"] != float64(1) {
		t.Fatalf("optionalJSON(obj) = %v, %v, %v", ok, err, obj)
	}

	var arr []int
	if ok, err := optionalJSON(req, "arr", 1024, &arr); err != nil || !ok || len(arr) != 2 {
		t.Fatalf("optionalJSON(arr) = %v, %v, %v", ok, err, arr)
	}

	// An absent argument is not an error and must leave the target alone.
	sentinel := map[string]any{"untouched": true}
	if ok, err := optionalJSON(req, "empty", 1024, &sentinel); ok || err != nil {
		t.Fatalf("optionalJSON(empty) = %v, %v", ok, err)
	}
	if !sentinel["untouched"].(bool) {
		t.Fatal("an absent argument overwrote the target")
	}

	if _, err := optionalJSON(req, "broken", 1024, &obj); err == nil {
		t.Error("malformed JSON was accepted")
	}
	if _, err := optionalJSON(req, "tooLong", 10, &obj); err == nil {
		t.Error("the size limit was not enforced")
	}

	// Decoding a scalar into a map is a type error the caller must see.
	if _, err := optionalJSON(req, "scalar", 1024, &obj); err == nil {
		t.Error("a scalar was accepted for an object target")
	}
}

func TestJSONObjectArg(t *testing.T) {
	req := newRequest("t", map[string]any{
		"obj":    `{"type":"user","id":"alice"}`,
		"arr":    `["alice"]`,
		"str":    `"alice"`,
		"num":    `42`,
		"null":   `null`,
		"bool":   `true`,
		"broken": `{oops}`,
	})

	raw, err := jsonObjectArg(req, "obj", 1024, true)
	if err != nil {
		t.Fatal(err)
	}
	// The bytes must come back exactly as they went in.
	if string(raw) != `{"type":"user","id":"alice"}` {
		t.Fatalf("raw = %s, want the argument unchanged", raw)
	}

	// Absent and optional is fine; absent and required is not.
	if raw, err := jsonObjectArg(req, "absent", 1024, false); err != nil || raw != nil {
		t.Fatalf("optional absent = %s, %v", raw, err)
	}
	if _, err := jsonObjectArg(req, "absent", 1024, true); err == nil {
		t.Error("a required argument was allowed to be absent")
	}

	// The error has to say what was found, so a model can fix it in one step
	// rather than guessing.
	for name, want := range map[string]string{
		"arr":  "an array",
		"str":  "a string",
		"num":  "a number",
		"null": "null",
		"bool": "a boolean",
	} {
		_, err := jsonObjectArg(req, name, 1024, true)
		if err == nil {
			t.Errorf("jsonObjectArg(%q) accepted a non-object", name)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("jsonObjectArg(%q) = %v, want it to say %q", name, err, want)
		}
	}

	if _, err := jsonObjectArg(req, "broken", 1024, true); err == nil {
		t.Error("malformed JSON was accepted")
	}
	if _, err := jsonObjectArg(req, "obj", 4, true); err == nil {
		t.Error("the size limit was not enforced")
	}
}

func TestRequireMembers(t *testing.T) {
	// Absent entities are the batch tool's per-entry override case; nothing to
	// check.
	if err := requireMembers(nil, "subject", "type", "id"); err != nil {
		t.Fatalf("an absent entity should pass: %v", err)
	}

	ok := []byte(`{"type":"user","id":"alice","properties":{"x":1}}`)
	if err := requireMembers(ok, "subject", "type", "id"); err != nil {
		t.Fatalf("a conformant subject was rejected: %v", err)
	}

	bad := map[string]string{
		`{"id":"alice"}`:                "type",
		`{"type":"user"}`:               "id",
		`{"type":"user","id":""}`:       "empty",
		`{"type":"user","id":7}`:        "string",
		`{"type":null,"id":"alice"}`:    "string",
		`{"type":{"a":1},"id":"alice"}`: "string",
	}
	for raw, want := range bad {
		err := requireMembers([]byte(raw), "subject", "type", "id")
		if err == nil {
			t.Errorf("requireMembers(%s) accepted it", raw)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("requireMembers(%s) = %v, want it to mention %q", raw, err, want)
		}
	}
}

func TestJSONKind(t *testing.T) {
	for in, want := range map[string]string{
		`null`: "null",
		`true`: "a boolean",
		`1.5`:  "a number",
		`"s"`:  "a string",
		`[1]`:  "an array",
	} {
		if _, err := asJSONObject([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("asJSONObject(%s) = %v, want it to say %q", in, err, want)
		}
	}
	if _, err := asJSONObject([]byte(`{"a":1}`)); err != nil {
		t.Errorf("asJSONObject rejected an object: %v", err)
	}
}

func TestOptionalNonNegativeInt(t *testing.T) {
	for _, tc := range []struct {
		in      any
		want    int
		absent  bool
		wantErr bool
	}{
		{in: nil, absent: true},
		{in: "", absent: true},
		{in: float64(0), want: 0},
		{in: float64(50), want: 50},
		{in: 7, want: 7},
		{in: "12", want: 12},
		{in: float64(-1), wantErr: true},
		{in: 1.5, wantErr: true},
		{in: "1.5", wantErr: true},
		{in: "x", wantErr: true},
		{in: true, wantErr: true},
		{in: float64(1 << 40), wantErr: true},
	} {
		args := map[string]any{}
		if tc.in != nil {
			args["n"] = tc.in
		}
		got, err := optionalNonNegativeInt(newRequest("t", args), "n")
		switch {
		case tc.wantErr:
			if err == nil {
				t.Errorf("%v: expected an error, got %v", tc.in, got)
			}
		case err != nil:
			t.Errorf("%v: %v", tc.in, err)
		case tc.absent:
			if got != nil {
				t.Errorf("%v: got %d, want absent", tc.in, *got)
			}
		case got == nil || *got != tc.want:
			t.Errorf("%v: got %v, want %d", tc.in, got, tc.want)
		}
	}
}
