/*
 * Copyright 2026 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/maritimeconnectivity/MMS/mmtp"
	"github.com/maritimeconnectivity/MMS/persistence"
	"github.com/maritimeconnectivity/MMS/utils/rw"
	"github.com/stretchr/testify/require"
)

// fakeSubjectControl stands in for the subject control service.
type fakeSubjectControl struct {
	mu sync.Mutex

	decisionStatus int
	decisionBody   string
	decisions      []string // "mrn subject action" of every decision asked

	allowlistStatus int
	allowlistBody   string
	allowlistETag   string
	cacheControl    string
	ifNoneMatch     []string // If-None-Match of every allowlist request

	server *httptest.Server
}

func newFakeSubjectControl(t *testing.T) *fakeSubjectControl {
	f := &fakeSubjectControl{
		decisionStatus: http.StatusOK, decisionBody: `{"decision":"DENY"}`,
		allowlistStatus: http.StatusOK, allowlistBody: `{"entries":[]}`, allowlistETag: `"empty"`,
		cacheControl: "max-age=600, stale-if-error=86400",
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/v1/decision":
			q := r.URL.Query()
			f.decisions = append(f.decisions, q.Get("mrn")+" "+q.Get("subject")+" "+q.Get("action"))
			w.WriteHeader(f.decisionStatus)
			fmt.Fprint(w, f.decisionBody)
		case "/v1/allowlist":
			f.ifNoneMatch = append(f.ifNoneMatch, r.Header.Get("If-None-Match"))
			if f.allowlistStatus != http.StatusOK {
				w.WriteHeader(f.allowlistStatus)
				return
			}
			w.Header().Set("ETag", f.allowlistETag)
			w.Header().Set("Cache-Control", f.cacheControl)
			if r.Header.Get("If-None-Match") == f.allowlistETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			fmt.Fprint(w, f.allowlistBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSubjectControl) set(change func(*fakeSubjectControl)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeSubjectControl) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.decisions...)
}

func (f *fakeSubjectControl) control() *subjectControl {
	return newSubjectControl(f.server.URL+"/", f.server.Client())
}

var knownAgent = &Agent{authenticated: true}

func init() { knownAgent.Mrn = "urn:mrn:mcp:entity:idp1:org1:agent" }

func TestSubjectControlOffAllowsEverything(t *testing.T) {
	var off *subjectControl
	require.True(t, off.allows(context.Background(), &Agent{}, "any", actionPublish))
}

func TestDecisionAllowsOnlyOn200Allow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"ALLOW", 200, `{"decision":"ALLOW"}`, true},
		{"DENY", 200, `{"decision":"DENY"}`, false},
		{"unknown word", 200, `{"decision":"MAYBE"}`, false},
		{"not JSON", 200, `ALLOW`, false},
		{"empty body", 200, ``, false},
		{"ALLOW with an error status", 503, `{"decision":"ALLOW"}`, false},
		{"403", 403, `{"error":"no role"}`, false},
		{"204", 204, ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeSubjectControl(t)
			fake.set(func(f *fakeSubjectControl) { f.decisionStatus, f.decisionBody = tc.status, tc.body })
			got := fake.control().allows(context.Background(), knownAgent, "urn:mrn:mcp:service:x:y", actionSubscribe)
			require.Equal(t, tc.want, got)
			require.Equal(t, []string{knownAgent.Mrn + " urn:mrn:mcp:service:x:y SUB"}, fake.asked())
		})
	}
}

func TestDecisionRefusesWhenTheServiceIsUnreachable(t *testing.T) {
	fake := newFakeSubjectControl(t)
	sc := fake.control()
	fake.server.Close()
	require.False(t, sc.allows(context.Background(), knownAgent, "s", actionPublish))
}

func TestDecisionRefusesWhenTheServiceIsSlow(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, `{"decision":"ALLOW"}`)
	}))
	defer slow.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	require.False(t, newSubjectControl(slow.URL, slow.Client()).allows(ctx, knownAgent, "s", actionPublish))
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestAnonymousAgentIsRefusedWithoutAsking(t *testing.T) {
	fake := newFakeSubjectControl(t)
	fake.set(func(f *fakeSubjectControl) {
		f.decisionBody = `{"decision":"ALLOW"}`
		f.allowlistBody = `{"entries":[{"pattern":".*","actions":["PUB","SUB"]}]}`
	})
	sc := fake.control()
	sc.refreshAllowlist(context.Background())

	require.False(t, sc.allows(context.Background(), &Agent{}, "open", actionSubscribe))
	require.Empty(t, fake.asked())
}

func TestAllowlistMatching(t *testing.T) {
	fake := newFakeSubjectControl(t)
	fake.set(func(f *fakeSubjectControl) {
		f.allowlistBody = `{"entries":[
			{"pattern":"urn:mrn:mcp:service:chatsea:notice:.*","actions":["SUB"]},
			{"pattern":"urn:mrn:mcp:service:chatsea:h3:[0-9a-f]{15}","actions":["PUB","SUB"]},
			{"pattern":"urn:mrn:mcp:service:chatsea:notice:kr","actions":["PUB"]},
			{"pattern":"urn:mrn:[","actions":["PUB","SUB"]},
			{"pattern":"","actions":["PUB","SUB"]}
		]}`
	})
	sc := fake.control()
	require.Equal(t, 10*time.Minute, sc.refreshAllowlist(context.Background()))
	require.Len(t, sc.entries, 3, "the two patterns that cannot be used are skipped")

	for _, tc := range []struct {
		name, subject, action string
		want                  bool
	}{
		{"'.*' crosses ':' boundaries", "urn:mrn:mcp:service:chatsea:notice:kr:busan", actionSubscribe, true},
		{"the action must be listed", "urn:mrn:mcp:service:chatsea:notice:kr:busan", actionPublish, false},
		{"entries that match add up", "urn:mrn:mcp:service:chatsea:notice:kr", actionPublish, true},
		{"the whole subject must match", "urn:mrn:mcp:service:chatsea:h3:8a2a1072b59ffff:extra", actionSubscribe, false},
		{"exact", "urn:mrn:mcp:service:chatsea:h3:8a2a1072b59ffff", actionPublish, true},
		{"a prefix is no match", "urn:mrn:mcp:service:chatsea:notice", actionSubscribe, false},
		{"case-sensitive", "URN:MRN:mcp:service:chatsea:notice:kr", actionSubscribe, false},
	} {
		require.Equal(t, tc.want, sc.onAllowlist(tc.subject, tc.action), tc.name)
	}

	// A listed subject needs no decision; any other subject does.
	require.True(t, sc.allows(context.Background(), knownAgent, "urn:mrn:mcp:service:chatsea:notice:kr:busan", actionSubscribe))
	require.Empty(t, fake.asked())
	require.False(t, sc.allows(context.Background(), knownAgent, "urn:mrn:mcp:service:chatsea:other", actionSubscribe))
	require.Len(t, fake.asked(), 1)
}

func TestAllowlistRefresh(t *testing.T) {
	fake := newFakeSubjectControl(t)
	fake.set(func(f *fakeSubjectControl) {
		f.allowlistBody, f.allowlistETag = `{"entries":[{"pattern":"open","actions":["SUB"]}]}`, `"v1"`
		f.cacheControl = "max-age=60, stale-if-error=3600"
	})
	sc := fake.control()
	now := time.Now()
	sc.now = func() time.Time { return now }
	ctx := context.Background()

	require.False(t, sc.onAllowlist("open", actionSubscribe), "nothing is allowed before the first list arrives")
	require.Equal(t, time.Minute, sc.refreshAllowlist(ctx))
	require.True(t, sc.onAllowlist("open", actionSubscribe))

	// Unchanged: 304, the list stays and the request carried the ETag.
	require.Equal(t, time.Minute, sc.refreshAllowlist(ctx))
	require.True(t, sc.onAllowlist("open", actionSubscribe))
	require.Equal(t, []string{"", `"v1"`}, fake.ifNoneMatch)

	// The service fails: retry soon, and keep using the list.
	fake.set(func(f *fakeSubjectControl) { f.allowlistStatus = http.StatusServiceUnavailable })
	require.Equal(t, allowlistRetry, sc.refreshAllowlist(ctx))
	now = now.Add(time.Hour)
	require.True(t, sc.onAllowlist("open", actionSubscribe), "still inside max-age + stale-if-error")

	// ... but not for ever.
	now = now.Add(2 * time.Minute)
	require.False(t, sc.onAllowlist("open", actionSubscribe), "the list has outlived stale-if-error")

	// A body that cannot be read does not replace the list either.
	fake.set(func(f *fakeSubjectControl) {
		f.allowlistStatus, f.allowlistBody, f.allowlistETag = http.StatusOK, `{"entries":`, `"broken"`
	})
	require.Equal(t, allowlistRetry, sc.refreshAllowlist(ctx))
	require.Equal(t, `"v1"`, sc.etag)

	// Back again with a changed list: replaced.
	fake.set(func(f *fakeSubjectControl) {
		f.allowlistBody, f.allowlistETag = `{"entries":[{"pattern":"other","actions":["PUB"]}]}`, `"v2"`
	})
	require.Equal(t, time.Minute, sc.refreshAllowlist(ctx))
	require.False(t, sc.onAllowlist("open", actionSubscribe))
	require.True(t, sc.onAllowlist("other", actionPublish))
}

func TestAllowlistIsFetchedAgainSoonAfterAFailedStart(t *testing.T) {
	fake := newFakeSubjectControl(t)
	sc := fake.control()
	fake.server.Close()
	require.Equal(t, allowlistRetry, sc.refreshAllowlist(context.Background()))
	require.Less(t, allowlistRetry, defaultAllowlistMaxAge)
}

func TestParseCacheControl(t *testing.T) {
	for header, want := range map[string][2]time.Duration{
		"max-age=600, stale-if-error=86400": {10 * time.Minute, 24 * time.Hour},
		"stale-if-error=5,max-age=1":        {time.Second, 5 * time.Second},
		"max-age=60":                        {time.Minute, 0},
		"":                                  {defaultAllowlistMaxAge, 0},
		"no-store":                          {defaultAllowlistMaxAge, 0},
		"max-age=0, stale-if-error=x":       {defaultAllowlistMaxAge, 0},
	} {
		maxAge, stale := parseCacheControl(header)
		require.Equal(t, want, [2]time.Duration{maxAge, stale}, header)
	}
}

func TestCheckSubjectControlFlags(t *testing.T) {
	require.NoError(t, checkSubjectControlFlags("", "", "", true), "off: nothing to check")
	require.NoError(t, checkSubjectControlFlags("https://sc.example:8443", "er.crt", "er.key", false))
	require.Error(t, checkSubjectControlFlags("https://sc.example:8443", "", "", false), "no client certificate")
	require.Error(t, checkSubjectControlFlags("https://sc.example:8443", "er.crt", "er.key", true), "insecure TLS")
	require.Error(t, checkSubjectControlFlags("http://sc.example", "er.crt", "er.key", false), "not https")
	require.Error(t, checkSubjectControlFlags("sc.example:8443", "er.crt", "er.key", false), "not a URL")
}

func TestRunRefusesSubjectControlWithoutClientCertificate(t *testing.T) {
	err := run([]string{"-subject-control", "https://sc.example:8443", "-db", ""})
	require.ErrorContains(t, err, "-client-cert")
}

// The tests below drive a real Agent connection, to prove where the check sits: a refused request
// must leave no trace in the Edge Router and must never reach the Router.

type authenticatedAgent struct {
	*testAgentConnection
	mrn string
	key *ecdsa.PrivateKey
}

// openAuthenticatedAgentConnection connects an Agent over TLS with an MCP-style client certificate,
// so the Edge Router treats it as authenticated. With mrn "" the Agent connects anonymously.
func openAuthenticatedAgentConnection(t *testing.T, mrn string) *authenticatedAgent {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	agentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject: pkix.Name{CommonName: "agent", ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: mrn},
		}},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	agentDER, err := x509.CreateCertificate(rand.Reader, agentTemplate, caCert, &agentKey.PublicKey, caKey)
	require.NoError(t, err)

	serverCtx, cancel := context.WithCancel(context.Background())
	ioCtx, ioCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn := &testAgentConnection{
		ctx: ioCtx, receive: make(chan *mmtp.MmtpMessage, 4), subs: make(map[string]*Subscription), subMu: &sync.RWMutex{},
		agents: make(map[string]*Agent), agentsMu: &sync.RWMutex{}, mrnToAgent: make(map[string]*Agent),
		mrnToAgentMu: &sync.RWMutex{}, store: persistence.NewMemoryStore(),
	}
	wg := &sync.WaitGroup{}
	server := httptest.NewUnstartedServer(handleHttpConnection(conn.receive, conn.subs, conn.subMu, conn.agents, conn.agentsMu,
		conn.mrnToAgent, conn.mrnToAgentMu, serverCtx, wg, conn.store))
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)
	server.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(ioCancel)
	t.Cleanup(cancel)

	transport := server.Client().Transport.(*http.Transport).Clone()
	if mrn != "" {
		transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{agentDER}, PrivateKey: agentKey}}
	}
	t.Cleanup(transport.CloseIdleConnections)
	conn.conn, _, err = websocket.Dial(ioCtx, "wss"+strings.TrimPrefix(server.URL, "https"),
		&websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.conn.Close(websocket.StatusNormalClosure, "test complete") })

	connect := newConnectMessage()
	if mrn != "" {
		connect.GetProtocolMessage().GetConnectMessage().OwnMrn = &mrn
	}
	a := &authenticatedAgent{testAgentConnection: conn, mrn: mrn, key: agentKey}
	require.Equal(t, mmtp.ResponseEnum_GOOD, a.request(t, connect))
	return a
}

// request sends a message and returns GOOD or ERROR from the Edge Router's response to it.
func (a *authenticatedAgent) request(t *testing.T, msg *mmtp.MmtpMessage) mmtp.ResponseEnum {
	t.Helper()
	require.NoError(t, rw.WriteMessage(a.ctx, a.conn, msg))
	response, _, err := rw.ReadMessage(a.ctx, a.conn)
	require.NoError(t, err)
	require.Equal(t, msg.GetUuid(), response.GetResponseMessage().GetResponseToUuid())
	return response.GetResponseMessage().GetResponse()
}

// sendMessage builds a Send message signed the way the Edge Router verifies it.
func (a *authenticatedAgent) sendMessage(t *testing.T, subject string, recipients ...string) *mmtp.MmtpMessage {
	t.Helper()
	body := []byte("hello")
	header := &mmtp.ApplicationMessageHeader{
		Expires: time.Now().Add(time.Hour).Unix(), Sender: a.mrn, BodySizeNumBytes: uint32(len(body)),
	}
	var signed []byte
	if len(recipients) > 0 {
		header.SubjectOrRecipient = &mmtp.ApplicationMessageHeader_Recipients{Recipients: &mmtp.Recipients{Recipients: recipients}}
		signed = append(signed, strings.Join(recipients, "")...)
	} else {
		header.SubjectOrRecipient = &mmtp.ApplicationMessageHeader_Subject{Subject: subject}
		signed = append(signed, subject...)
	}
	signed = append(signed, strconv.FormatInt(header.Expires, 10)...)
	signed = append(signed, a.mrn...)
	signed = append(signed, strconv.Itoa(len(body))...)
	signed = append(signed, body...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)

	return &mmtp.MmtpMessage{
		MsgType: mmtp.MsgType_PROTOCOL_MESSAGE,
		Uuid:    uuid.NewString(),
		Body: &mmtp.MmtpMessage_ProtocolMessage{ProtocolMessage: &mmtp.ProtocolMessage{
			ProtocolMsgType: mmtp.ProtocolMessageType_SEND_MESSAGE,
			Body: &mmtp.ProtocolMessage_SendMessage{SendMessage: &mmtp.Send{
				ApplicationMessage: &mmtp.ApplicationMessage{Header: header, Body: body, Signature: signature},
			}},
		}},
	}
}

// forwarded returns the message the Edge Router passed on towards the Router, or nil if there is none.
func (a *authenticatedAgent) forwarded() *mmtp.MmtpMessage {
	select {
	case msg := <-a.receive:
		return msg
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

func useSubjectControl(t *testing.T, fake *fakeSubjectControl) {
	t.Helper()
	sc := fake.control()
	sc.refreshAllowlist(context.Background())
	subjectCtl = sc
	t.Cleanup(func() { subjectCtl = nil })
}

const (
	testAgentMrn = "urn:mrn:mcp:entity:idp1:org1:agent"
	testSubject  = "urn:mrn:mcp:service:idp1:org1:notice"
)

func TestSubscribeIsCheckedBySubjectControl(t *testing.T) {
	fake := newFakeSubjectControl(t)
	useSubjectControl(t, fake)
	agent := openAuthenticatedAgentConnection(t, testAgentMrn)

	t.Run("refused: ERROR, nothing registered, nothing sent to the Router", func(t *testing.T) {
		require.Equal(t, mmtp.ResponseEnum_ERROR, agent.request(t, newSubscribeMessage(testSubject)))
		require.Nil(t, agent.forwarded())
		agent.subMu.RLock()
		require.Empty(t, agent.subs)
		agent.subMu.RUnlock()
		for _, session := range agent.agents {
			stored, err := agent.store.Subscriptions(agent.ctx, session.ID)
			require.NoError(t, err)
			require.Empty(t, stored)
		}
		require.Equal(t, []string{testAgentMrn + " " + testSubject + " SUB"}, fake.asked())
	})

	t.Run("allowed: GOOD, and the subscription goes to the Router", func(t *testing.T) {
		fake.set(func(f *fakeSubjectControl) { f.decisionBody = `{"decision":"ALLOW"}` })
		subscribe := newSubscribeMessage(testSubject)
		require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, subscribe))
		forwarded := agent.forwarded()
		require.NotNil(t, forwarded)
		require.Equal(t, subscribe.GetUuid(), forwarded.GetUuid())
		agent.subMu.RLock()
		require.Contains(t, agent.subs, testSubject)
		agent.subMu.RUnlock()
	})
}

func TestSubjectCastSendIsCheckedBySubjectControl(t *testing.T) {
	fake := newFakeSubjectControl(t)
	useSubjectControl(t, fake)
	agent := openAuthenticatedAgentConnection(t, testAgentMrn)

	t.Run("refused: ERROR, and the message never reaches the Router", func(t *testing.T) {
		require.Equal(t, mmtp.ResponseEnum_ERROR, agent.request(t, agent.sendMessage(t, testSubject)))
		require.Nil(t, agent.forwarded())
		require.Equal(t, []string{testAgentMrn + " " + testSubject + " PUB"}, fake.asked())
	})

	t.Run("allowed: GOOD, and the message goes to the Router", func(t *testing.T) {
		fake.set(func(f *fakeSubjectControl) { f.decisionBody = `{"decision":"ALLOW"}` })
		send := agent.sendMessage(t, testSubject)
		require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, send))
		forwarded := agent.forwarded()
		require.NotNil(t, forwarded)
		require.Equal(t, send.GetUuid(), forwarded.GetUuid())
	})

	t.Run("the service is down: ERROR", func(t *testing.T) {
		fake.set(func(f *fakeSubjectControl) { f.decisionStatus = http.StatusServiceUnavailable })
		require.Equal(t, mmtp.ResponseEnum_ERROR, agent.request(t, agent.sendMessage(t, testSubject)))
		require.Nil(t, agent.forwarded())
	})
}

func TestDirectlyAddressedSendIsNotChecked(t *testing.T) {
	fake := newFakeSubjectControl(t) // answers DENY to everything
	useSubjectControl(t, fake)
	agent := openAuthenticatedAgentConnection(t, testAgentMrn)

	require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, agent.sendMessage(t, "", "urn:mrn:mcp:entity:idp1:org1:other")))
	require.NotNil(t, agent.forwarded())
	require.Empty(t, fake.asked())
}

func TestAllowlistedSubjectNeedsNoDecision(t *testing.T) {
	fake := newFakeSubjectControl(t) // answers DENY to every decision
	fake.set(func(f *fakeSubjectControl) {
		f.allowlistBody = `{"entries":[{"pattern":"urn:mrn:mcp:service:idp1:org1:.*","actions":["SUB"]}]}`
	})
	useSubjectControl(t, fake)
	agent := openAuthenticatedAgentConnection(t, testAgentMrn)

	require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, newSubscribeMessage(testSubject)))
	require.NotNil(t, agent.forwarded())
	require.Empty(t, fake.asked())

	// The entry lists SUB only, so publishing still needs a decision, and that is DENY.
	require.Equal(t, mmtp.ResponseEnum_ERROR, agent.request(t, agent.sendMessage(t, testSubject)))
	require.Equal(t, []string{testAgentMrn + " " + testSubject + " PUB"}, fake.asked())
}

func TestAnonymousAgentCannotSubscribeWhenSubjectControlIsOn(t *testing.T) {
	fake := newFakeSubjectControl(t)
	fake.set(func(f *fakeSubjectControl) {
		f.decisionBody = `{"decision":"ALLOW"}`
		f.allowlistBody = `{"entries":[{"pattern":".*","actions":["PUB","SUB"]}]}`
	})
	useSubjectControl(t, fake)
	agent := openAuthenticatedAgentConnection(t, "")

	require.Equal(t, mmtp.ResponseEnum_ERROR, agent.request(t, newSubscribeMessage(testSubject)))
	require.Nil(t, agent.forwarded())
	require.Empty(t, fake.asked())
}

func TestWithoutSubjectControlNothingChanges(t *testing.T) {
	require.Nil(t, subjectCtl)
	agent := openAuthenticatedAgentConnection(t, testAgentMrn)
	require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, newSubscribeMessage(testSubject)))
	require.NotNil(t, agent.forwarded())
	require.Equal(t, mmtp.ResponseEnum_GOOD, agent.request(t, agent.sendMessage(t, testSubject)))
	require.NotNil(t, agent.forwarded())
}
