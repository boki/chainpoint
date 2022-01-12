package chainpoint

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

type (
	// ParsedChainpoint ...
	ParsedChainpoint struct {
		Hash         string
		ProofID      string
		HashReceived Time
		Branches     []ParsedBranch
	}

	// ParsedBranch ...
	ParsedBranch struct {
		Label         string
		Branches      []ParsedBranch
		Anchors       []ParsedAnchor
		OpReturnValue string
		BTCTxID       string
	}

	// ParsedAnchor ...
	ParsedAnchor struct {
		Type          string
		AnchorID      string
		URIs          []string
		ExpectedValue string
	}
)

// Parse ...
func Parse(chp *Chainpoint) (*ParsedChainpoint, error) {
	branches, err := parseBranches(chp.Hash, chp.Branches)
	if err != nil {
		return nil, err
	}
	pchp := &ParsedChainpoint{
		Hash:         chp.Hash,
		ProofID:      chp.ProofID,
		HashReceived: chp.HashReceived,
		Branches:     branches,
	}
	return pchp, nil
}

// parseBranches acquires all anchor points and calcaulte expected values for
// all branches, recursively.
func parseBranches(hash string, branches []Branch) ([]ParsedBranch, error) {
	curHash, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	parsedBranched := []ParsedBranch{}
	for _, b := range branches {
		anchors := []ParsedAnchor{}
		for _, op := range b.Ops {
			if op.R != "" {
				// hex data gets treated as hex, otherwise it is converted to bytes assuming a ut8 encoded string
				var val []byte
				if isHex(op.R) {
					val, _ = hex.DecodeString(op.R)
				} else {
					val = []byte(op.R)
				}
				curHash = concat(curHash, val)
			} else if op.L != "" {
				// hex data gets treated as hex, otherwise it is converted to bytes assuming a ut8 encoded string
				var val []byte
				if isHex(op.L) {
					val, _ = hex.DecodeString(op.L)
				} else {
					val = []byte(op.L)
				}
				curHash = concat(val, curHash)
			} else if op.Op != OpUnknown {
				switch op.Op {
				case OpSHA224:
					h := sha256.Sum224(curHash)
					curHash = h[:]
					break
				case OpSHA256:
					h := sha256.Sum256(curHash)
					curHash = h[:]
					break
				case OpSHA384:
					h := sha512.Sum384(curHash)
					curHash = h[:]
					break
				case OpSHA512:
					h := sha512.Sum512(curHash)
					curHash = h[:]
					break
				case OpSHA3224:
					h := sha3.Sum224(curHash)
					curHash = h[:]
					break
				case OpSHA3256:
					h := sha3.Sum256(curHash)
					curHash = h[:]
					break
				case OpSHA3384:
					h := sha3.Sum384(curHash)
					curHash = h[:]
					break
				case OpSHA3512:
					h := sha3.Sum512(curHash)
					curHash = h[:]
					break
				case OpSHA256x2:
					h := sha256.Sum256(curHash)
					h = sha256.Sum256(h[:])
					curHash = h[:]
					break
				default:
					return nil, fmt.Errorf("unknown op: %s", op.Op)
				}
			} else if len(op.Anchors) > 0 {
				anchors = append(anchors, parseAnchors(hex.EncodeToString(curHash), op.Anchors)...)
			}
		}
		branch := ParsedBranch{
			Label:   b.Label,
			Anchors: anchors,
		}
		if len(b.Branches) > 0 {
			branch.Branches, _ = parseBranches(hex.EncodeToString(curHash), b.Branches)
		}

		// if this branch is a standard Chaipoint BTC anchor branch,
		// output the OP_RETURN value and the BTC transaction id
		if b.Label == "btc_anchor_branch" {
			opReturnValue, btcTxID, err := btcAnchorInfo(hash, b.Ops)
			if err != nil {
				return nil, err
			}
			branch.OpReturnValue = opReturnValue
			branch.BTCTxID = btcTxID
		}
		parsedBranched = append(parsedBranched, branch)
	}
	return parsedBranched, nil
}

// parseAnchors ...
func parseAnchors(curHash string, anchorsArray []Anchor) []ParsedAnchor {
	anchors := []ParsedAnchor{}
	for _, a := range anchorsArray {
		expectedValue := curHash
		// BTC merkle root values is in little endian byte order
		// All hashes and calculations in a Chainpoint proof are in big endian byte order
		// If we are determining the expected value for a BTC anchor, the expected value
		// result byte order must be reversed to match the BTC merkle root byte order
		// before making any comparisons
		switch a.Type {
		case AnchorBTC:
			r := strings.Builder{}
			l := len(expectedValue)
			for i := 0; i < l; i += 2 {
				r.WriteByte(expectedValue[l-i-2])
				r.WriteByte(expectedValue[l-i-1])
			}
			expectedValue = r.String()
		case AnchorTBTC:
		}
		anchors = append(anchors, ParsedAnchor{
			Type:          a.Type,
			AnchorID:      a.AnchorID,
			URIs:          a.URIs,
			ExpectedValue: expectedValue,
		})
	}
	return anchors
}

func btcAnchorInfo(startHash string, ops []Operation) (string, string, error) {
	// This calculation depends on the branch using the standard format
	// for btc_anchor_branch type branches created by Chainpoint services
	curHash, err := hex.DecodeString(startHash)
	if err != nil {
		return "", "", err
	}
	type opResult struct {
		OpResult []byte
		Op       Operation
	}
	opRes := []opResult{}
	btcTxIDOpIndex := -1
	for _, op := range ops {
		if op.R != "" {
			// hex data gets treated as hex, otherwise it is converted to bytes assuming a ut8 encoded string
			var val []byte
			if isHex(op.R) {
				val, _ = hex.DecodeString(op.R)
			} else {
				val = []byte(op.R)
			}
			curHash = concat(val, curHash)
			opRes = append(opRes, opResult{OpResult: curHash, Op: op})
		} else if op.L != "" {
			// hex data gets treated as hex, otherwise it is converted to bytes assuming a ut8 encoded string
			var val []byte
			if isHex(op.L) {
				val, _ = hex.DecodeString(op.L)
			} else {
				val = []byte(op.L)
			}
			curHash = concat(curHash, val)
			opRes = append(opRes, opResult{OpResult: curHash, Op: op})
		} else if op.Op != OpUnknown {
			switch op.Op {
			case OpSHA224:
				h := sha256.Sum224(curHash)
				curHash = h[:]
				break
			case OpSHA256:
				h := sha256.Sum256(curHash)
				curHash = h[:]
				break
			case OpSHA384:
				h := sha512.Sum384(curHash)
				curHash = h[:]
				break
			case OpSHA512:
				h := sha512.Sum512(curHash)
				curHash = h[:]
				break
			case OpSHA3224:
				h := sha3.Sum224(curHash)
				curHash = h[:]
				break
			case OpSHA3256:
				h := sha3.Sum256(curHash)
				curHash = h[:]
				break
			case OpSHA3384:
				h := sha3.Sum384(curHash)
				curHash = h[:]
				break
			case OpSHA3512:
				h := sha3.Sum512(curHash)
				curHash = h[:]
				break
			case OpSHA256x2:
				h := sha256.Sum256(curHash)
				h = sha256.Sum256(h[:])
				curHash = h[:]
				if btcTxIDOpIndex == -1 {
					btcTxIDOpIndex = len(opRes)
				}
				break
			default:
				return "", "", fmt.Errorf("unknown op: %s", op.Op)
			}
			opRes = append(opRes, opResult{OpResult: curHash, Op: op})
		}
	}

	opReturnOpIndex := btcTxIDOpIndex - 3
	opReturnValue := hex.EncodeToString(opRes[opReturnOpIndex].OpResult)
	btcTxID := reverseHex(hex.EncodeToString(opRes[btcTxIDOpIndex].OpResult))
	return opReturnValue, btcTxID, nil
}

func reverseHex(s string) string {
	r := strings.Builder{}
	l := len(s)
	for i := 0; i < l; i += 2 {
		r.WriteByte(s[l-i-2])
		r.WriteByte(s[l-i-1])
	}
	return r.String()
}

func concat(a, b []byte) []byte {
	r := make([]byte, len(a)+len(b))
	bp := copy(r, a)
	copy(r[bp:], b)
	return r
}
