package securityverify

import (
	"net/http"
)

// SVClient calls Security verify APIs
type SVClient interface {
	// addAuthorization to the provided request
	addAuthorization(r *http.Request) (*http.Request, error)

	// tenant invoked by this client
	Tenant() string
}

// svProtocolClient knows the HTTP protocol requirements for a given api.
type svProtocolClient interface {
	SVClient

	// addContentType to the provided request
	addContentType(r *http.Request) *http.Request

	// addAccepts headers to the provided request
	addAccepts(r *http.Request) *http.Request

	// client used for HTTP requests
	client() *http.Client
}

// DecoratedClient allows someone to affix their own changes to a given request
type DecoratedClient interface {
	svProtocolClient

	// Decorate the request - default impl does nothing
	DecorateRequest(r *http.Request) *http.Request
}

type decorator struct {
	decoratorFunc func(*http.Request) *http.Request
}

func (d *decorator) SetDecorator(f func(*http.Request) *http.Request) *decorator {
	d.decoratorFunc = f
	return d
}

func (d *decorator) DecorateRequest(r *http.Request) *http.Request {
	if d.decoratorFunc != nil {
		return d.decoratorFunc(r)
	}
	return r
}

func newDecorator() *decorator {
	return &decorator{decoratorFunc: nil}
}
