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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// Subject control asks an external service whether an Agent may publish or subscribe to a subject.
//
// Two things are asked of the service:
//   - GET /v1/allowlist: subject patterns every authenticated Agent may use. The list is kept in
//     memory and refreshed in the background, so these subjects need no further request.
//   - GET /v1/decision?mrn=&subject=&action=: asked for every other subject-cast Send and subject
//     Subscribe. Only a 200 answer saying ALLOW lets the request through; a denial, an error and
//     an unreachable service all refuse it.
//
// Existing subscriptions are asked about again after every allowlist refresh, and dropped when the
// service says DENY.
//
// The Agent only ever sees the standard MMTP GOOD or ERROR response.

const (
	actionPublish   = "PUB"
	actionSubscribe = "SUB"

	decisionAllow = "ALLOW"
	decisionDeny  = "DENY"

	// decisionTimeout bounds one decision request, so a slow service cannot stall an Agent's connection.
	decisionTimeout = 3 * time.Second
	// allowlistRetry is how soon a failed allowlist request is tried again.
	allowlistRetry = 30 * time.Second
	// defaultAllowlistMaxAge is used when the response carries no usable max-age.
	defaultAllowlistMaxAge = 10 * time.Minute
)

// subjectCtl is nil when subject control is off, which leaves every Agent request as it was.
// It is a package variable rather than a parameter to keep the handlers' signatures untouched.
var subjectCtl *subjectControl

type allowEntry struct {
	pattern *regexp.Regexp
	actions map[string]bool
}

type subjectControl struct {
	baseURL string
	client  *http.Client
	now     func() time.Time

	mu         sync.RWMutex
	entries    []allowEntry
	etag       string
	validUntil time.Time // the kept allowlist must not be used after this
}

func newSubjectControl(baseURL string, client *http.Client) *subjectControl {
	return &subjectControl{baseURL: strings.TrimSuffix(baseURL, "/"), client: client, now: time.Now}
}

// allows reports whether the Agent may do the action on the subject. A nil receiver allows everything.
func (sc *subjectControl) allows(ctx context.Context, agent *Agent, subject, action string) bool {
	if sc == nil {
		return true
	}
	// An anonymous Agent has no MRN to hold a permission, and the allowlist is for authenticated Agents.
	if !agent.authenticated || agent.Mrn == "" {
		return false
	}
	if sc.onAllowlist(subject, action) {
		return true
	}
	return sc.decide(ctx, agent.Mrn, subject, action)
}

// onAllowlist reports whether a kept, still usable allowlist entry covers the subject and action.
func (sc *subjectControl) onAllowlist(subject, action string) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.now().After(sc.validUntil) {
		return false
	}
	for _, e := range sc.entries {
		if e.actions[action] && e.pattern.MatchString(subject) {
			return true
		}
	}
	return false
}

// decide asks the service. Anything but a 200 response saying ALLOW is a refusal.
func (sc *subjectControl) decide(ctx context.Context, mrn, subject, action string) bool {
	decision, err := sc.decision(ctx, mrn, subject, action)
	if err != nil {
		log.Warn("Subject control decision failed, refusing:", err)
		return false
	}
	return decision == decisionAllow
}

// decision returns what the service answered. An error means it gave no answer, which is not a denial.
func (sc *subjectControl) decision(ctx context.Context, mrn, subject, action string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, decisionTimeout)
	defer cancel()

	query := url.Values{"mrn": {mrn}, "subject": {subject}, "action": {action}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc.baseURL+"/v1/decision?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := sc.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		Decision string `json:"decision"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Decision, nil
}

// keepAllowlistFresh fetches the allowlist now and again whenever it is due, until ctx ends.
// After every successful fetch it calls afterRefresh, which is when existing subscriptions are
// checked again. A failed fetch skips it: with the service down nothing could be learned.
func (sc *subjectControl) keepAllowlistFresh(ctx context.Context, wg *sync.WaitGroup, afterRefresh func(context.Context)) {
	defer wg.Done()
	for {
		wait, ok := sc.refreshAllowlist(ctx)
		if ok && afterRefresh != nil {
			afterRefresh(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refreshAllowlist asks for the allowlist once. It returns how long to wait before asking again and
// whether the service answered. The kept list is replaced only by a 200 response. A 304 keeps it
// and extends its life. Any failure leaves it as it is, to be used until validUntil.
func (sc *subjectControl) refreshAllowlist(ctx context.Context) (time.Duration, bool) {
	ctx, cancel := context.WithTimeout(ctx, decisionTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc.baseURL+"/v1/allowlist", nil)
	if err != nil {
		log.Error("Could not create subject control allowlist request:", err)
		return allowlistRetry, false
	}
	sc.mu.RLock()
	etag := sc.etag
	sc.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := sc.client.Do(req)
	if err != nil {
		log.Warn("Subject control allowlist request failed, keeping the current list:", err)
		return allowlistRetry, false
	}
	defer resp.Body.Close()

	maxAge, staleIfError := parseCacheControl(resp.Header.Get("Cache-Control"))
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Entries []struct {
				Pattern string   `json:"pattern"`
				Actions []string `json:"actions"`
			} `json:"entries"`
		}
		if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
			log.Warn("Could not read subject control allowlist, keeping the current list:", err)
			return allowlistRetry, false
		}
		entries := make([]allowEntry, 0, len(body.Entries))
		for _, e := range body.Entries {
			pattern, compileErr := compileSubjectPattern(e.Pattern)
			if compileErr != nil {
				log.Warnf("Skipping allowlist pattern %q: %v", e.Pattern, compileErr)
				continue
			}
			actions := make(map[string]bool, len(e.Actions))
			for _, a := range e.Actions {
				actions[a] = true
			}
			entries = append(entries, allowEntry{pattern: pattern, actions: actions})
		}
		sc.mu.Lock()
		sc.entries, sc.etag = entries, resp.Header.Get("ETag")
		sc.validUntil = sc.now().Add(maxAge + staleIfError)
		sc.mu.Unlock()
		log.Infof("Subject control allowlist updated, %d entries", len(entries))
		return maxAge, true
	case http.StatusNotModified:
		sc.mu.Lock()
		sc.validUntil = sc.now().Add(maxAge + staleIfError)
		sc.mu.Unlock()
		return maxAge, true
	default:
		log.Warnf("Subject control answered an allowlist request with %d, keeping the current list", resp.StatusCode)
		return allowlistRetry, false
	}
}

// recheckSubscriptions drops the subject subscriptions the service no longer allows, so that a
// permission that expired or was revoked stops the Agent from receiving, not only from subscribing anew.
//
// A subscription is dropped only on an explicit DENY. No answer keeps it: an outage of the service
// must not unsubscribe everyone. The Agent is not told, as MMTP has no message for that.
func (er *EdgeRouter) recheckSubscriptions(ctx context.Context) {
	sc := subjectCtl
	if sc == nil {
		return
	}
	type held struct {
		agent   *Agent
		subject string
	}
	var subscriptions []held
	er.subMu.RLock()
	for subject, sub := range er.subscriptions {
		for _, agent := range sub.SnapshotSubscribers() {
			subscriptions = append(subscriptions, held{agent, subject})
		}
	}
	er.subMu.RUnlock()

	dropped := 0
	for _, s := range subscriptions {
		if ctx.Err() != nil {
			return
		}
		// A subscription without an MRN was made anonymously, before subject control was switched on.
		if s.agent.Mrn != "" {
			if sc.onAllowlist(s.subject, actionSubscribe) {
				continue
			}
			decision, err := sc.decision(ctx, s.agent.Mrn, s.subject, actionSubscribe)
			if err != nil {
				log.Warn("Could not recheck a subscription, keeping it:", err)
				continue
			}
			if decision != decisionDeny {
				continue
			}
		}
		if err := er.dropSubscription(ctx, s.agent, s.subject); err != nil {
			log.Error("Could not drop a subscription that is no longer allowed:", err)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		log.Infof("Dropped %d subscriptions that subject control no longer allows", dropped)
	}
}

// dropSubscription removes one Agent's subscription to a subject, and the Edge Router's own
// subscription at the Router when that was the last Agent. The Agent's Interests are left alone:
// they belong to the goroutine serving its connection and are only used to clean up on disconnect.
func (er *EdgeRouter) dropSubscription(ctx context.Context, agent *Agent, subject string) error {
	if err := er.store.Unsubscribe(ctx, agent.ID, subject); err != nil {
		return err
	}
	unsubscribeUpstream := false
	er.subMu.Lock()
	if sub := er.subscriptions[subject]; sub != nil {
		sub.DeleteSubscriber(agent)
		if len(sub.SnapshotSubscribers()) == 0 {
			delete(er.subscriptions, subject)
			unsubscribeUpstream = true
		}
	}
	er.subMu.Unlock()
	if unsubscribeUpstream {
		er.outgoingChannel <- newUpstreamSubscription(subject, false)
	}
	return nil
}

// checkSubjectControlFlags refuses flag combinations that could never work or would not be safe.
func checkSubjectControlFlags(subjectControlURL, clientCert, clientCertKey string, insecure bool) error {
	if subjectControlURL == "" {
		return nil
	}
	parsed, err := url.Parse(subjectControlURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("-subject-control must be an https URL")
	}
	// The service identifies this Edge Router by its client certificate.
	if clientCert == "" || clientCertKey == "" {
		return fmt.Errorf("-subject-control needs -client-cert and -client-cert-key")
	}
	// Without server verification anyone on the path could answer ALLOW.
	if insecure {
		return fmt.Errorf("-subject-control cannot be combined with -i")
	}
	return nil
}

// compileSubjectPattern compiles an allowlist pattern so that it has to match the whole subject,
// whether or not the pattern itself is anchored.
func compileSubjectPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}

// parseCacheControl reads max-age and stale-if-error. A missing or unusable max-age becomes the
// default; a missing stale-if-error means the list may not outlive max-age.
func parseCacheControl(header string) (maxAge, staleIfError time.Duration) {
	maxAge = defaultAllowlistMaxAge
	for _, directive := range strings.Split(header, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds < 0 {
			continue
		}
		switch strings.ToLower(name) {
		case "max-age":
			if seconds > 0 {
				maxAge = time.Duration(seconds) * time.Second
			}
		case "stale-if-error":
			staleIfError = time.Duration(seconds) * time.Second
		}
	}
	return maxAge, staleIfError
}
