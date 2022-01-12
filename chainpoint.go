// Package chainpoint provides functionality to access the Chainpoint Node API.
//
// A Chainpoint Node allows anyone to run a server that accepts hashes, anchors
// them to public blockchains, creates and verifies proofs, and participates in
// the Chainpoint Network.
package chainpoint

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vmihailenco/msgpack"
)

// UserAgent is the header string used to identify this package.
const UserAgent = "Chainpoint Node API Go Client"

// OpEnum ...
type OpEnum string

// OpEnums introduced by package chainpoint.
const (
	OpUnknown  OpEnum = ""
	OpSHA224   OpEnum = "sha-224"
	OpSHA256   OpEnum = "sha-256"
	OpSHA384   OpEnum = "sha-384"
	OpSHA512   OpEnum = "sha-512"
	OpSHA3224  OpEnum = "sha3-224"
	OpSHA3256  OpEnum = "sha3-256"
	OpSHA3384  OpEnum = "sha3-384"
	OpSHA3512  OpEnum = "sha3-512"
	OpSHA256x2 OpEnum = "sha-256-x2"
)

const (
	// ChpContext is the value for Chainpoint.Context
	ChpContext = "https://w3id.org/chainpoint/v4"
	// ChpType is the value for Chainpoint.Type
	ChpType = "Chainpoint"
)

type (
	// Time ...
	Time string

	// Chainpoint ...
	Chainpoint struct {
		Context      string   `json:"@context"`
		Type         string   `json:"type"`
		Hash         string   `json:"hash"`
		ProofID      string   `json:"proof_id"`
		HashReceived Time     `json:"hash_received"`
		Branches     []Branch `json:"branches"`
	}

	// Branch ...
	Branch struct {
		Label    string      `json:"label,omitempty"`
		Branches []Branch    `json:"branches,omitempty"`
		Ops      []Operation `json:"ops"`
	}

	// Operation ...
	Operation struct {
		L       string   `json:"l,omitempty"`
		R       string   `json:"r,omitempty"`
		Op      OpEnum   `json:"op,omitempty"`
		Anchors []Anchor `json:"anchors,omitempty"`
	}

	// Anchor ...
	Anchor struct {
		Type     string   `json:"type"`
		AnchorID string   `json:"anchor_id"`
		URIs     []string `json:"uris,omitempty"`
	}
)

// Anchors ...
const (
	AnchorCal  = "cal"
	AnchorBTC  = "btc"
	AnchorETH  = "eth"
	AnchorTCal = "tcal"
	AnchorTBTC = "tbtc"
)

const timeLayoutISO8601 = "2006-01-02T15:04:05Z"

// NewTime ...
func NewTime(t time.Time) Time {
	return Time(t.Format(timeLayoutISO8601))
}

func (t Time) String() string {
	return string(t)
}

// Time ...
func (t Time) Time() (time.Time, error) {
	return time.Parse(timeLayoutISO8601, string(t))
}

// Valid returns a value indicating whether the Chainpoint is valid.
func (chp *Chainpoint) Valid() bool {
	if chp.Context != ChpContext {
		return false
	}
	if chp.Type != ChpType {
		return false
	}
	if !isHex(chp.Hash) || len(chp.Hash) < 40 || len(chp.Hash) > 128 {
		return false
	}
	if string(chp.HashReceived) == "" {
		return false
	}
	for _, b := range chp.Branches {
		if !b.Valid() {
			return false
		}
	}
	return len(chp.Branches) > 0
}

// Valid returns a value indicating whether the Branch is valid.
func (br Branch) Valid() bool {
	// ^[a-zA-Z0-9-_.]{1,64}$
	if l := len(br.Label); l < 1 || l > 64 {
		return false
	}
	for _, r := range br.Label {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	for _, b := range br.Branches {
		if !b.Valid() {
			return false
		}
	}
	return br.Label == "aggregator" || len(br.Ops) > 0
}

// Valid returns a value indicating whether the Operation is valid.
func (op Operation) Valid() bool {
	if l := len(op.L); l == 0 || l > 512 {
		return false
	}
	if l := len(op.R); l == 0 || l > 512 {
		return false
	}
	if op.Op != OpUnknown {
		return false
	}
	for _, a := range op.Anchors {
		if !a.Valid() {
			return false
		}
	}
	return true
}

// Valid returns a value indicating whether the Anchor is valid.
func (a Anchor) Valid() bool {
	// ^[a-z]{3,10}$
	if l := len(a.Type); l < 3 || l > 10 {
		return false
	}
	for _, r := range a.Type {
		if !(r >= 'a' && r <= 'z') {
			return false
		}
	}
	if l := len(a.AnchorID); l == 0 || l > 512 {
		return false
	}
	for _, u := range a.URIs {
		if l := len(u); l == 0 || l > 512 {
			return false
		}
	}
	return true
}

// MarshalBinary ...
func (chp *Chainpoint) MarshalBinary() ([]byte, error) {
	if !chp.Valid() {
		return nil, errors.New("chainpoint v4 schema invalid")
	}
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	enc := msgpack.NewEncoder(w).UseJSONTag(true)
	if err := enc.Encode(&chp); err != nil {
		return nil, err
	}
	err = w.Close()
	return buf.Bytes(), err
}

// UnmarshalBinary unmarshales text into the Chainpoint structure.
func (chp *Chainpoint) UnmarshalBinary(proof []byte) error {
	if len(proof) == 0 {
		return errors.New("no binary proof provided")
	}
	r, err := zlib.NewReader(bytes.NewReader(proof))
	if err != nil {
		return err
	}
	defer r.Close()
	dec := msgpack.NewDecoder(r).UseJSONTag(true)
	if err := dec.Decode(&chp); err != nil {
		return err
	}
	if !chp.Valid() {
		return errors.New("chainpoint v3 schema invalid")
	}
	return nil
}

// Error response from Chainpoint APIs.
type Error struct {
	statusCode int
	msg        string
}

// NewError retruns a new Error given a status code and message.
func NewError(code int, msg string) *Error {
	return &Error{
		statusCode: code,
		msg:        msg,
	}
}

// Error returns the string representation of the error.
func (e *Error) Error() string {
	return fmt.Sprintf("Error %d: %s", e.statusCode, e.msg)
}

// IsPerm gets a value indicating whether the error is a permission error.
func IsPerm(err error) bool {
	e, ok := err.(*Error)
	return ok && e.statusCode == http.StatusUnauthorized
}

// IsTemporary gets a value indicating whether the error is a temporary error.
func IsTemporary(err error) bool {
	e, ok := err.(*Error)
	return ok && e.statusCode == http.StatusConflict
}
