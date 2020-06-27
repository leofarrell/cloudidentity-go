package securityverify

import "net/http"

type svJSONClient struct {
	*decorator
	tkn     SVClient
	client_ *http.Client
}

func newSVJSONClient(tkn SVClient) *svJSONClient {
	return &svJSONClient{client_: &http.Client{}, tkn: tkn, decorator: newDecorator()}
}

func (sv *svJSONClient) addAuthorization(r *http.Request) (*http.Request, error) {
	return sv.tkn.addAuthorization(r)
}

func (sv *svJSONClient) addContentType(r *http.Request) *http.Request {
	r.Header.Add("Content-type", contentTypeJSON)
	return r
}

func (sv *svJSONClient) addAccepts(r *http.Request) *http.Request {
	r.Header.Add("Accept", contentTypeJSON)
	return r
}

func (sv *svJSONClient) client() *http.Client {
	return sv.client_
}

func (sv *svJSONClient) Tenant() string {
	return sv.tkn.Tenant()
}
