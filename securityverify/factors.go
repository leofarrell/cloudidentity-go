package securityverify

import "net/http"

// Factors API provider
func (c *SVJSONClient) Factors() *FactorsClient {
	return &FactorsClient{client: c}

}

// Factors API provider
func (c *SVAPIClient) Factors() *FactorsClient {
	return &FactorsClient{client: NewSVJSONClient(c)}

}

// Factors API provider
func (bt *BearerToken) Factors() *FactorsClient {
	return &FactorsClient{client: NewSVJSONClient(bt)}
}

// FactorsClient calls all APIs relevent to authentication factors
// These APIs are invoked with a bearer token issued to a user or API client
type FactorsClient struct {
	client *SVJSONClient
}

// SetDecorator to be used in requests with this FactorsClient
func (f *FactorsClient) SetDecorator(fn func(*http.Request) *http.Request) {
	f.client.decoratorFunc = fn
}

// FactorsEnrollment contains the common fields of all the V2 factors APIs
type FactorsEnrollment struct {
	ID        string `json:"id,omitempty"`
	UserID    string `json:"userId"`
	Enabled   bool   `json:"enabled"`
	Updated   string `json:"updated"`
	Created   string `json:"created"`
	Attempted string `json:"attempted"`

	// TODO there are more fields which are generic
}
