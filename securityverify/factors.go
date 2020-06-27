package securityverify

import "net/http"

// Factors API provider
func (c *svJSONClient) Factors() *FactorsClient {
	return &FactorsClient{client: c}

}

// Factors API provider
func (c *SVAPIClient) Factors() *FactorsClient {
	return &FactorsClient{client: newSVJSONClient(c)}

}

// Factors API provider
func (bt *BearerToken) Factors() *FactorsClient {
	return &FactorsClient{client: newSVJSONClient(bt)}
}

// FactorsClient calls all APIs relevent to authentication factors
// These APIs are invoked with a bearer token issued to a user or API client
type FactorsClient struct {
	client *svJSONClient
}

// SetDecorator to be used in requests with this FactorsClient
func (f *FactorsClient) SetDecorator(fn func(*http.Request) *http.Request) {
	f.client.SetDecorator(fn)
}

type factorsBase struct {
	ID      string `json:"id,omitempty"`
	UserID  string `json:"userId"`
	Enabled bool   `json:"enabled"`
	Updated string `json:"updated"`
	Created string `json:"created"`
	Type    string `json:"type"`

	// TODO there are more fields which are generic
}

type factorsEnrollment struct {
	factorsBase
	Attempted string `json:"attempted"`
}

type factorsAssertion struct {
	Assertion string `json:"assertion"`
}
