package chainpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/satori/go.uuid"
)

const (
	libVersion = "v1.0.0"
	userAgent  = UserAgent + "/" + libVersion + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
)

// ContentTypes supported in responses.
const (
	ContentTypeJSON   = "application/vnd.chainpoint.ld+json"
	ContentTypeBase64 = "application/vnd.chainpoint.json+base64"
)

// A Service is a Chainpoint Node API client.
type Service struct {
	client    *http.Client
	lookupTXT func(name string) ([]string, error)
	UserAgent string // optional additional User-Agent fragment
}

// New initializes and returns a Service with given options.
func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, NewError(0, "client is nil")
	}
	c := &Service{
		client:    client,
		lookupTXT: net.LookupTXT,
	}
	return c, nil
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return userAgent
	}
	return s.UserAgent + " " + userAgent
}

var rxCoreURIHostWhitelist = regexp.MustCompile("^[a-z]\\.chainpoint\\.org$")

// validCoreURI checks if uri is a valid Core URI.
func validCoreURI(uri string) bool {
	if uri == "" {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return u.Scheme == "https" &&
		rxCoreURIHostWhitelist.MatchString(u.Host)
}

func validNodeURI(uri string) bool {
	if uri == "" {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "0.0.0.0" {
		return false
	}
	ip := net.ParseIP(u.Host)
	return ip.To4() != nil
}

// ProcessingHints ...
type ProcessingHints map[string]time.Time

// Next returns the processing hint that is closest to t, or 0, if all hints
// are less than t.
func (h ProcessingHints) Next(t time.Time) time.Time {
	tt := []time.Time{}
	for _, ph := range h {
		if t.Before(ph) {
			tt = append(tt, ph)
		}
	}
	if len(tt) == 0 {
		return time.Time{}
	}
	sort.SliceStable(tt, func(i, j int) bool {
		return tt[i].Before(tt[j])
	})
	return tt[0]
}

// HashItem ...
type HashItem struct {
	ProofID string `json:"proof_id"`
	Hash    string `json:"hash"`
}

// PostHash ...
type PostHash struct {
	URI  string `json:"uri,omitempty"`
	Meta struct {
		SubmittedAt     time.Time       `json:"submitted_at"`
		ProcessingHints ProcessingHints `json:"processing_hints"`
	} `json:"meta"`
	Hashes []HashItem `json:"hashes"`
}

// isHex retruns a value indicating whether s is a hexadecimal string.
func isHex(s string) bool {
	if l := len(s); l%2 != 0 || l < 2 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// uniq removes duplicates from the array a.
func uniq(a []string) []string {
	l := len(a)
	for i := 0; i < l; i++ {
		s := a[i]
		for j := i + 1; j < l; j++ {
			if s == a[j] {
				a[j] = a[l-1]
				a = a[:l-1]
				l--
				j--
			}
		}
	}
	return a
}

// Hashes submits one or more hashes to one Node, returning an array of proof
// handle objects, one for each submitted hash.
func (s *Service) Hashes(ctx context.Context, uri string, hashes []string) (*PostHash, error) {
	// 200: successful operation
	// 409: invalid argument in request
	// Validate all hashes provided
	if l := len(hashes); l == 0 {
		return nil, errors.New("no hashes")
	} else if l > 250 {
		return nil, errors.New("hashes must be <= 250")
	}
	rejects := []string{}
	for _, h := range hashes {
		if !isHex(h) {
			rejects = append(rejects, h)
		}
	}
	if len(rejects) > 0 {
		return nil, fmt.Errorf("invalid hashes: %v", rejects)
	}
	if !validNodeURI(uri) {
		return nil, fmt.Errorf("invalid Node URI")
	}

	body := struct {
		Hashes []string `json:"hashes"`
	}{
		Hashes: hashes,
	}
	jsonBody, err := json.Marshal(&body)
	if err != nil {
		return nil, err
	}
	// Setup an Request for each Node we'll submit hashes to.
	// Each Node will then be sent the full array of hashes.
	req, err := http.NewRequest("POST", uri+"/hashes", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	type response struct {
		res *PostHash
		err error
	}
	var phr *PostHash
	err = func() error {
		err := s.do(req, &phr)
		if err != nil {
			return err
		}
		// Nodes cannot be guaranteed to know what IP address they are reachable
		// at, so we need to amend each result with the Node URI it was submitted
		// to so that proofs may later be retrieved from the appropriate Node(s).
		phr.URI = uri
		return nil
	}()
	return phr, err
}

// Proof ...
type Proof struct {
	ProofID          string          `json:"proof_id"`         // The Version 1 UUID used to retrieve the proof.
	Proof            json.RawMessage `json:"proof"`            // The JSON or Base64 encoded binary form of the proof.
	AnchorsCompleted []string        `json:"anchors_complete"` // An Array that indicates which blockchains the proof is anchored to at the time of retrieval.
}

// validUUID returns a value indicating whether the specified uuid is a valid v1
// UUID.
func validUUID(s string) bool {
	u, err := uuid.FromString(s)
	return err == nil && u.Version() == 1
}

// Proofs retrieves a collection of proofs for one or more hash IDs from the
// specified Node URI.
func (s *Service) Proofs(ctx context.Context, nodeURI string, proofIDs []string, contentType ...string) ([]*Proof, error) {
	if !validNodeURI(nodeURI) {
		return nil, fmt.Errorf("invalid URI: %s", nodeURI)
	}
	if len(proofIDs) == 0 {
		return nil, errors.New("empty proofIDs")
	}
	rejects := []string{}
	for _, h := range proofIDs {
		if !validUUID(h) {
			rejects = append(rejects, h)
		}
	}
	if len(rejects) > 0 {
		return nil, fmt.Errorf("invalid proofIDs UUIDs in proofHandles: %v", rejects)
	}
	respCntType := ContentTypeJSON
	if len(contentType) > 0 {
		if respCntType = contentType[0]; respCntType != ContentTypeJSON && respCntType != ContentTypeBase64 {
			return nil, fmt.Errorf("unsupported content type %q", respCntType)
		}
	}
	req, err := http.NewRequest("GET", nodeURI+"/proofs", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", respCntType)
	req.Header.Add("proofids", strings.Join(proofIDs, ","))
	/*type response struct {
		ProofID          string          `json:"proof_id"`         // The Version 1 UUID used to retrieve the proof.
		Proof            json.RawMessage `json:"proof"`            // The Base64 encoded binary form of the proof.
		AnchorsCompleted []string        `json:"anchors_complete"` // An Array that indicates which blockchains the proof is anchored to at the time of retrieval.
	}*/
	var proofs []*Proof
	if err := s.do(req, &proofs); err != nil {
		return nil, err
	}
	return proofs, nil
}

// VerifyResponseAnchor ...
type VerifyResponseAnchor struct {
	Branch string `json:"branch"`
	Type   string `json:"type"`
	Valid  bool   `json:"valid"`
}

// VerifyResponse ...
type VerifyResponse struct {
	ProofIndex   int                    `json:"proof_index"`
	Hash         string                 `json:"hash"`
	HashCore     string                 `json:"hash_core"`
	HashReceived time.Time              `json:"hash_received"`
	Anchors      []VerifyResponseAnchor `json:"anchors"`
	Status       string                 `json:"status"`
}

// Verify submits one or more proofs for verification.
func (s *Service) Verify(ctx context.Context, uri string, proofs []*Chainpoint) ([]*VerifyResponse, error) {
	if !validNodeURI(uri) {
		return nil, errors.New("invalid Node URI")
	}
	data, err := json.Marshal(map[string]interface{}{"proofs": proofs})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", uri+"/verify", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	var res []*VerifyResponse
	if err := s.do(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// CalendarResponse ...
type CalendarResponse struct {
	ID       int    `json:"id"`
	Time     int    `json:"time"`
	Version  int    `json:"version"`
	StackID  string `json:"stackId"`
	Type     string `json:"type"`
	DataID   string `json:"dataId"`
	DataVal  string `json:"dataVal"`
	PrevHash string `json:"prevHash"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig"`
}

// Calendar retrieves the calendar block at the given height.
func (s *Service) Calendar(ctx context.Context, uri, height string) (*CalendarResponse, error) {
	if !validNodeURI(uri) {
		return nil, errors.New("invalid Node URI")
	}
	req, err := http.NewRequest("GET", uri+"/calendar/"+height, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	var res *CalendarResponse
	if err := s.do(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// CalendarHash retrieves the calendar block hash at the given height.
func (s *Service) CalendarHash(ctx context.Context, uri, height string) (string, error) {
	if !validNodeURI(uri) {
		return "", errors.New("invalid Node URI")
	}
	req, err := http.NewRequest("GET", uri+"/calendar/"+height+"/hash", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	var res string
	if err := s.do(req, &res); err != nil {
		return "", err
	}
	return res, nil
}

// CalendarData retrieves the calendar block data_val at the given height.
func (s *Service) CalendarData(ctx context.Context, uri, height string) (string, error) {
	if !validNodeURI(uri) {
		return "", errors.New("invalid Node URI")
	}
	req, err := http.NewRequest("GET", uri+"/calendar/"+height+"/data", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	var res string
	if err := s.do(req, &res); err != nil {
		return "", err
	}
	return res, nil
}

// ConfigResponse ...
type ConfigResponse struct {
	Version             string    `json:"version"`
	ProofExpireMinutes  int       `json:"proof_expire_minutes"`
	GetProofsMaxRest    int       `json:"get_proofs_max_rest"`
	PostHashesMax       int       `json:"post_hashes_max"`
	PostVerifyProofsMax int       `json:"post_verify_proofs_max"`
	Time                time.Time `json:"time"`
	Calendar            struct {
		Height        int    `json:"height"`
		AuditResponse string `json:"audit_response"`
	} `json:"calendar"`
}

// Config retrieves the configuration information for the Node.
func (s *Service) Config(ctx context.Context, uri string) (*ConfigResponse, error) {
	if !validNodeURI(uri) {
		return nil, errors.New("invalid Node URI")
	}
	req, err := http.NewRequest("GET", uri+"/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	var res *ConfigResponse
	if err := s.do(req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) do(req *http.Request, v interface{}) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.userAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer closeBody(resp)
	d := json.NewDecoder(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		errMsg := map[string]string{}
		err = d.Decode(&errMsg)
		if err != nil {
			return err
		}
		msg, ok := errMsg["error"]
		if !ok {
			msg = "No details"
		}
		return NewError(resp.StatusCode, msg)
	} else if s, ok := v.(*string); ok {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		*s = string(b)
		return nil
	}
	return d.Decode(&v)
}

func newJSONReader(v interface{}) (io.Reader, error) {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(v)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func closeBody(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	res.Body.Close()
}
