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

// Tenant to which this client belongs
func (sv *OIDCClient) Tenant() string {
	return sv.tenantID
}

// SetTenant for this token
func (sv *OIDCClient) SetTenant(tenant string) {
	sv.tenantID = tenant
}

func (sv *OIDCClient) client() *http.Client {
	return sv.client_
}

// BearerToken is issued to an OIDC client on behalf of a user.
// This type is not used by the API client.
// A BearerToken is in itssself a client - however it will only be able to request APIs to which it is entitled.
type BearerToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TenantID     string
}

func (bt *BearerToken) addAuthorization(r *http.Request) (*http.Request, error) {
	r.Header.Set("authorization", fmt.Sprintf("Bearer %s", bt.AccessToken))
	return r, nil
}

// SetTenant for this token
func (bt *BearerToken) SetTenant(tenant string) {
	bt.TenantID = tenant
}

// Tenant to which this token belongs
func (bt *BearerToken) Tenant() string {
	return bt.TenantID
}

func (oidc *OIDCClient) Token(grantType string, scope string, extra url.Values) (*BearerToken, error) {
	bearer := &BearerToken{TenantID: oidc.tenantID}
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

type IntrospectResponseExtension struct {
	TenantId string `json:tenantId,omitempty`
}

type IntrospectResponse struct {
	Active       bool                         `json:"active"`
	Exp          int64                        `json:"exp"`
	ClientID     string                       `json:"client_id"`
	Scope        string                       `json:"scope"`
	Sub          string                       `json:"sub"`
	TokenType    string                       `json:"token_type"`
	GrantType    string                       `json:"grant_type"`
	Entitlements []string                     `json:"entitlements,omitempty"`
	Ext          *IntrospectResponseExtension `json:"ext"`
}

func (oidc *OIDCClient) Introspect(token string, extra url.Values, output interface{}) error {
	if extra == nil {
		extra = url.Values{}
	} else {
		extra.Del("client_id")
		extra.Del("client_secret")
	}

	extra.Add("token", token)
	extra.Add("client_id", oidc.ClientID)
	extra.Add("client_secret", oidc.ClientSecret)

	rsp, err := post(oidc, urlOidcIntrospect, strings.NewReader(extra.Encode()), 200)
	if err != nil {
		return err
	}

	json.NewDecoder(rsp.Body).Decode(output)

	return nil
}
