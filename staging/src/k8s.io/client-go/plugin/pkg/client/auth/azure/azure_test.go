/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azure

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"net/http"
	"github.com/Azure/go-autorest/autorest/adal"
)

func TestAzureTokenSourceCaching(t *testing.T) {
	fakeAccessToken := "fake token 1"
	fakeSource := fakeTokenSource{
		accessToken: fakeAccessToken,
		expiresOn:   strconv.FormatInt(time.Now().Add(3600*time.Second).Unix(), 10),
	}
	cfg := make(map[string]string)
	persiter := &fakePersister{cache: make(map[string]string)}
	tokenCache := newAzureTokenCache()
	tokenSource := newAzureTokenSource(&fakeSource, tokenCache, cfg, persiter, &fakeTokenRefresher{})
	token, err := tokenSource.Token()
	if err != nil {
		t.Errorf("failed to retrieve the token from fake tokenSource: %v", err)
	}

	wantCacheLen := 1
	if len(tokenCache.cache) != wantCacheLen {
		t.Errorf("Token() cache length error: got %v, want %v", len(tokenCache.cache), wantCacheLen)
	}

	if token != tokenCache.cache[azureTokenKey] {
		t.Error("Token() returned token != cached token")
	}

	wantCfg := token2Cfg(token)
	persistedCfg := persiter.Cache()

	wantCfgLen := len(wantCfg)
	persistedCfgLen := len(persistedCfg)
	if wantCfgLen != persistedCfgLen {
		t.Errorf("wantCfgLen and persistedCfgLen do not match, wantCfgLen=%v, persistedCfgLen=%v", wantCfgLen, persistedCfgLen)
	}

	for k, v := range persistedCfg {
		if strings.Compare(v, wantCfg[k]) != 0 {
			t.Errorf("Token() persisted cfg %s: got %v, want %v", k, v, wantCfg[k])
		}
	}

	fakeSource.accessToken = "fake token 2"
	token, err = tokenSource.Token()
	if err != nil {
		t.Errorf("failed to retrieve the cached token: %v", err)
	}

	if token.token.AccessToken != fakeAccessToken {
		t.Errorf("Token() didn't return the cached token")
	}
}

// func fakeRefreshToken()
func TestAzureTokenSourceRetrieveFromCfg(t *testing.T) {
	fakeSource := newFakeTokenSource("cfg token", time.Now().Add(3600*time.Second))
	// generate token to cfg
	targetToken, err := fakeSource.Token()
	// err is ignored as it's part of test

	cfg := token2Cfg(targetToken)
	fakeSource.accessToken = "wrong token"
	persiter := newFakePersister()
	tokenCache := newAzureTokenCache()
	tokenSource := newAzureTokenSource(&fakeSource, tokenCache, cfg, &persiter, &fakeTokenRefresher{})
	token, err := tokenSource.Token()
	if err != nil {
		t.Errorf("failed to retrieve the token from cfg: %v", err)
	}
	if token.token.AccessToken != "cfg token" {
		t.Errorf("Got wrong token %s, should be \"cfg token\"", token.token.AccessToken)
	}
	if persiter.calls > 0 {
		t.Errorf("persister.Persist() was unexpectedly called %d times", persiter.calls)
	}
}

func TestAzureTokenSourceExtending(t *testing.T) {
	expiredSource := newFakeTokenSource("expired token", time.Now().Add(-time.Second))
	expiredToken, _ := expiredSource.Token()
	extendedSource := newFakeTokenSource("extend token", time.Now().Add(1000*time.Second))
	extendedToken, _ := extendedSource.Token()
	fakeSource := newFakeTokenSource("fake token", time.Now().Add(1000*time.Second))
	
	// take 1, successful extend
	cfg := make(map[string]string)
	persister := newFakePersister()
	tokenCache := newAzureTokenCache()
	// set expiredToken to cache directly
	tokenCache.setToken(azureTokenKey, expiredToken)

	refresher := fakeTokenRefresher{
		token: extendedToken,
	}
	t.Logf("refresher.token: %v", refresher.token)
	tokenSource := newAzureTokenSource(&fakeSource, tokenCache, cfg, &persister, &refresher)
	token, err := tokenSource.Token()
	t.Logf("got token: %v", token)
	if err != nil {
		t.Errorf("Failed to retrieve the token: %v", err)
	}
	if token.token.AccessToken != "extend token" {
		t.Errorf("Got wrong token %s, should be \"extend token\"", token.token.AccessToken)
	}
	if fakeSource.calls > 0 {
		t.Errorf("fakeSource.Token() should never be called, got %d", fakeSource.calls)
	}
	if persister.calls != 1 {
		t.Errorf("persister.Persist() should be called exactly once, got %d", persister.calls)
	}
	cachedToken := tokenCache.getToken(azureTokenKey)
	if cachedToken.token.AccessToken != "extend token" {
		t.Errorf("Expect token set to cache, got %v", cachedToken)
	}

	// take 2, failed extend
	refreshErr := fakeTokenRefreshError{
		message: "FakeError happened when refreshing",
		// response is left as nil as not actually required.
	}
	// reset cache
	tokenCache.setToken(azureTokenKey, expiredToken)
	refresher = fakeTokenRefresher{
		token: nil,
		err:   refreshErr,
	}
	tokenSource = newAzureTokenSource(&fakeSource, tokenCache, cfg, &persister, &refresher)
	token, err = tokenSource.Token()
	t.Logf("got token: %v", token)
	if err != nil {
		t.Errorf("Failed to retrieve the token: %v", err)
	}
	if token.token.AccessToken != "fake token" {
		t.Errorf("Got wrong token %s, should be \"fake token\"", token.token.AccessToken)
	}
	if fakeSource.calls != 1 {
		t.Errorf("fakeSource.Token() should never be called, got %d", fakeSource.calls)
	}
}


type fakePersister struct {
	lock  sync.Mutex
	cache map[string]string
	calls uint
}

func newFakePersister() fakePersister {
	return fakePersister{cache: make(map[string]string), calls: 0}
}


func (p *fakePersister) Persist(cache map[string]string) error {
	p.lock.Lock()
	defer p.lock.Unlock()
    p.calls ++
	p.cache = map[string]string{}
	for k, v := range cache {
		p.cache[k] = v
	}
	return nil
}

func (p *fakePersister) Cache() map[string]string {
	ret := map[string]string{}
	p.lock.Lock()
	defer p.lock.Unlock()
	for k, v := range p.cache {
		ret[k] = v
	}
	return ret
}

type fakeTokenSource struct {
	expiresOn   string
	accessToken string
	calls       uint
}

func newFakeTokenSource(accessToken string, expiresOnTime time.Time) fakeTokenSource {
	return fakeTokenSource{
		expiresOn: strconv.FormatInt(expiresOnTime.Unix(), 10),
		accessToken: accessToken,
		calls: 0,
	}
}

func (ts *fakeTokenSource) Token() (*azureToken, error) {
	ts.calls ++
	return &azureToken{
		token:       newFakeAzureToken(ts.accessToken, ts.expiresOn),
		environment: "testenv",
		clientID:    "fake",
		tenantID:    "fake",
		apiserverID: "fake",
	}, nil
}

func token2Cfg(token *azureToken) map[string]string {
	cfg := make(map[string]string)
	cfg[cfgAccessToken] = token.token.AccessToken
	cfg[cfgRefreshToken] = token.token.RefreshToken
	cfg[cfgEnvironment] = token.environment
	cfg[cfgClientID] = token.clientID
	cfg[cfgTenantID] = token.tenantID
	cfg[cfgApiserverID] = token.apiserverID
	cfg[cfgExpiresIn] = string(token.token.ExpiresIn)
	cfg[cfgExpiresOn] = string(token.token.ExpiresOn)
	return cfg
}

func newFakeAzureToken(accessToken string, expiresOn string) adal.Token {
	return adal.Token{
		AccessToken:  accessToken,
		RefreshToken: "fake",
		ExpiresIn:    "3600",
		ExpiresOn:    json.Number(expiresOn),
		NotBefore:    json.Number(expiresOn),
		Resource:     "fake",
		Type:         "fake",
	}
}

type fakeTokenRefresher struct {
	calls uint
	err   error
	token *azureToken
}

func (ts *fakeTokenRefresher) refreshToken(token* azureToken) (*azureToken, error) {
	return ts.token, ts.err
}

// copied from go-autorest/adal
type fakeTokenRefreshError struct {
	message string
	resp    *http.Response
}

// Error implements the error interface which is part of the TokenRefreshError interface.
func (tre fakeTokenRefreshError) Error() string {
	return tre.message
}

// Response implements the TokenRefreshError interface, it returns the raw HTTP response from the refresh operation.
func (tre fakeTokenRefreshError) Response() *http.Response {
	return tre.resp
}