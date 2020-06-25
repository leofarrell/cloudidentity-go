package securityverify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type OIDCClient struct {
	tenantID     string
	client_      *http.Client
	ClientID     string
	ClientSecret string
}

func NewOIDCClient(clientId, clientSecret, tenant string) *OIDCClient {
	return &OIDCClient{
		tenantID:     tenant,
		client_:      &http.Client{},
		ClientID:     clientId,
		ClientSecret: clientSecret}
}
func (sv *OIDCClient) addAuthorization(r *http.Request) (*http.Request, error) {
	r.SetBasicAuth(sv.ClientID, sv.ClientSecret)
	return r, nil
}

func (sv *OIDCClient) addContentType(r *http.Request) *http.Request {
	r.Header.Add("Content-Type", contentTypeForm)
	return r
}

func (sv *OIDCClient) addAccepts(r *http.Request) *http.Request {
	r.Header.Add("Accept", contentTypeJSON)
	return r
}

func (sv *OIDCClient) Tenant() string {
	return sv.tenantID
}

func (sv *OIDCClient) client() *http.Client {
	return sv.client_
}

type BearerToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	tenant       string
}

func (bt *BearerToken) addAuthorization(r *http.Request) (*http.Request, error) {
	r.Header.Set("authorization", fmt.Sprintf("Bearer %s", bt.AccessToken))
	return r, nil
}

func (bt *BearerToken) SetTenant(tenant string) {
	bt.tenant = tenant
}

func (bt *BearerToken) Tenant() string {
	return bt.tenant
}

func (oidc *OIDCClient) Token(grantType string, scope string, extra url.Values) (*BearerToken, error) {
	bearer := &BearerToken{tenant: oidc.tenantID}
	err := oidc.TokenRef(grantType, scope, extra, bearer)
	if err != nil {
		return nil, err
	}

	return bearer, nil
}

func (oidc *OIDCClient) TokenRef(grantType string, scope string, extra url.Values, output interface{}) error {

	extra.Del("grant_type")
	extra.Del("client_id")
	extra.Del("client_secret")

	extra.Add("grant_type", grantType)
	extra.Add("scope", scope)
	extra.Add("client_id", oidc.ClientID)
	extra.Add("client_secret", oidc.ClientSecret)

	rsp, err := post(oidc, urlOidcToken, strings.NewReader(extra.Encode()), 200)

	if err != nil {
		return err
	}

	json.NewDecoder(rsp.Body).Decode(output)
	return nil
}
