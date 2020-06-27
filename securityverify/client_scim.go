package securityverify

import "net/http"

type svSCIMClient struct {
	tkn     SVClient
	client_ *http.Client
}

func newSVSCIMClient(tkn SVClient) *svSCIMClient {
	return &svSCIMClient{client_: &http.Client{}, tkn: tkn}
}

func (sv *svSCIMClient) addAuthorization(r *http.Request) (*http.Request, error) {
	return sv.tkn.addAuthorization(r)
}

func (sv *svSCIMClient) addContentType(r *http.Request) *http.Request {
	r.Header.Add("Content-type", contentTypeSCIM)
	return r
}

func (sv *svSCIMClient) addAccepts(r *http.Request) *http.Request {
	r.Header.Add("Accept", contentTypeSCIM)
	return r
}

func (sv *svSCIMClient) Tenant() string {
	return sv.tkn.Tenant()
}

func (sv *svSCIMClient) client() *http.Client {
	return sv.client_
}
