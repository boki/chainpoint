package chainpoint

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestParse(t *testing.T) {
	rawJSON, err := ioutil.ReadFile("testdata/chainpoint-proof-v4.chp.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var chp *Chainpoint
	if err := json.Unmarshal(rawJSON, &chp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := Parse(chp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, _ := json.MarshalIndent(&res, "", "  ")
	fmt.Printf("%v\n", string(b))
	//t.Fail()
	if got, exp := len(res.Branches), 1; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
	if got, exp := len(res.Branches[0].Branches), 1; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
	if got, exp := len(res.Branches[0].Branches[0].Anchors), 1; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
	if got, exp := len(res.Branches[0].Branches[0].Branches), 1; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
	if got, exp := len(res.Branches[0].Branches[0].Branches[0].Anchors), 1; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
	if got, exp := res.Branches[0].Branches[0].Branches[0].Anchors[0].ExpectedValue, "e8886527b676a2d835e8fd8417b3884c0158ff7ec38647012fe15f5ae448d825"; got != exp {
		t.Fatalf("got %v; want %v", got, exp)
	}
}

func TestReverseHex(t *testing.T) {
	testCases := map[string]struct {
		s   string
		exp string
	}{
		"Simple": {"1122334455", "5544332211"},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got, exp := reverseHex(tc.s), tc.exp; got != exp {
				t.Errorf("got %s; want %s", got, exp)
			}
		})
	}
}
