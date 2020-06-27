package securityverify

import (
	"log"
	"os"
)

const (
	urlOidcToken      = "/v1.0/endpoint/default/token"
	urlOidcIntrospect = "/v1.0/endpoint/default/introspect"

	urlFactorsUsenamePassword = "/v1.0/authnmethods/password"
	urlFactorsEmailotp        = "/v2.0/factors/emailotp"

	urlIdentitySources = "/v1.0/identitysources"
	urlUsers           = "/v2.0/Users"
)

// Some content types
const (
	contentTypeJSON = "application/json"
	contentTypeSCIM = "application/scim+json"
	contentTypeForm = "application/x-www-form-urlencoded"
)

// Some ISV specific constants
const (
	constCloudDirectory = "Cloud Directory"

	constVerifications = "verifications"
)

// Some SCIM specific constants
const (
	scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
)

var svlog = log.New(os.Stderr, "[ securityverify ]", log.Ltime|log.Lshortfile)
