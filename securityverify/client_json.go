package securityverify

import "net/http"

type SVJSONClient struct {
	*decorator
	tkn     SVClient
	client_ *http.Client
}

func NewSVJSONClient(tkn SVClient) *SVJSONClient {
	return &SVJSONClient{client_: &http.Client{}, tkn: tkn, decorator: newDecorator()}
}

func (sv *SVJSONClient) addAuthorization(r *http.Request) (*http.Request, error) {
	return sv.tkn.addAuthorization(r)
}

func (sv *SVJSONClient) addContentType(r *http.Request) *http.Request {
	r.Header.Add("Content-type", contentTypeJSON)
	return r
}

func (sv *SVJSONClient) addAccepts(r *http.Request) *http.Request {
	r.Header.Add("Accept", contentTypeJSON)
	return r
}

func (sv *SVJSONClient) client() *http.Client {
	return sv.client_
}

func (sv *SVJSONClient) Tenant() string {
	return sv.tkn.Tenant()
}
