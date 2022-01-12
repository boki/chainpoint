package chainpoint

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "update .golden files")

func TestTimeNewTime(t *testing.T) {
	tt, err := time.Parse("2006-01-02T15:04:05Z", "2019-01-07T12:45:00Z")
	if err != nil {
		t.Fatalf("unexepected error: %v", err)
	}
	testCases := map[string]struct {
		t   time.Time
		exp Time
	}{
		"Zero": {time.Time{}, "0001-01-01T00:00:00Z"},
		"Date": {tt, Time("2019-01-07T12:45:00Z")},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := NewTime(tc.t), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestTimeTime(t *testing.T) {
	tt, err := time.Parse("2006-01-02T15:04:05Z", "2019-01-07T12:45:00Z")
	if err != nil {
		t.Fatalf("unexepected error: %v", err)
	}
	testCases := map[string]struct {
		t   Time
		exp time.Time
		err string
	}{
		"Zero": {Time(""), time.Time{}, `parsing time "" as "2006-01-02T15:04:05Z": cannot parse "" as "2006"`},
		"Date": {Time("2019-01-07T12:45:00Z"), tt, ""},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.t.Time()
			if (tc.err != "" && err == nil) || (err != nil && err.Error() != tc.err) {
				t.Fatalf("got: %v; want %v", err, tc.err)
			}
			if exp := tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestOperationMarshal(t *testing.T) {
	testCases := map[string]struct {
		op  Operation
		exp string
	}{
		"no anchors": {Operation{L: "left", R: "right", Op: OpSHA512, Anchors: []Anchor{}}, `{"l":"left","r":"right","op":"sha-512"}`},
		"one anchor": {Operation{L: "left", R: "right", Op: OpSHA512, Anchors: []Anchor{{"type", "id", []string{"uri"}}}}, `{"l":"left","r":"right","op":"sha-512","anchors":[{"type":"type","anchor_id":"id","uris":["uri"]}]}`},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(&tc.op)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, exp := string(data), tc.exp; got != exp {
				t.Errorf("got %v; want %v", got, exp)
			}
		})
	}
}

func TestChainpointMarshalBinary(t *testing.T) {
	jsonProof, err := ioutil.ReadFile(filepath.Join("samples", "chainpoint-proof-v4.chp.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	chp := &Chainpoint{}
	if err := json.Unmarshal(jsonProof, &chp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := chp.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	golden := filepath.Join("testdata", "chainpoint-proof-v4.chp.golden")
	if *update {
		ioutil.WriteFile(golden, got, 0644)
	}
	exp, err := ioutil.ReadFile(golden)
	if err != nil {
		t.Fatalf("failed to load golden file: %v", err)
	}
	if !bytes.Equal(got, exp) {
		t.Fatalf("got %v; want %v\n", got, exp)
	}
}

func TestChainpointUnmarshalBinary(t *testing.T) {
	jsonProof, err := ioutil.ReadFile(filepath.Join("samples", "chainpoint-proof-v4.chp.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exp := &Chainpoint{}
	if err := json.Unmarshal(jsonProof, &exp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	proof, err := ioutil.ReadFile(filepath.Join("samples", "chainpoint-proof-v4.chp"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := &Chainpoint{}
	err = got.UnmarshalBinary(proof)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("got %+v; want %+v", got, exp)
	}
}

func TestChainpointUnmarshalBinaryBase64(t *testing.T) {
	jsonProof, err := ioutil.ReadFile(filepath.Join("samples", "chainpoint-proof-v4.chp.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exp := &Chainpoint{}
	if err := json.Unmarshal(jsonProof, &exp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	proof, err := ioutil.ReadFile(filepath.Join("samples", "chainpoint-proof-v4.chp.b64"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bin := make([]byte, len(proof))
	if _, err := base64.StdEncoding.Decode(bin, proof); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := &Chainpoint{}
	err = got.UnmarshalBinary(bin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("got %+v; want %+v", got, exp)
	}
}
