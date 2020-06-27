package securityverify

import (
	"encoding/json"
	"fmt"
)

type upRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UPAttribute is returned as part of a Username Password API request
type UPAttribute struct {
	Values []string `json:"values"`
	Name   string   `json:"name"`
}

// UPGroup is returned as part of a Username Password API request
type UPGroup struct {
	SourceID    string `json:"sourceId"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
}

// UPResult is the structure returned by the UsernamePassword API
type UPResult struct {
	Attributes []UPAttribute `json:"attributes"`
	Groups     []UPGroup     `json:"groups"`
	ID         string        `json:"id"`
}

// UsernamePassword API - validate a username and password against a given identity source.
// See https://myidp.ice.ibmcloud.com/developer/explorer/#!/Password_Authentication_Method/authenticateWithPassword
func (f *FactorsClient) UsernamePassword(username, password, identitysource string, result interface{}) error {

	up := upRequest{Username: username, Password: password}

	r := outputPipe(&up)

	url := fmt.Sprintf("%s/%s", urlFactorsUsenamePassword, identitysource)
	status, err := post(f.client, url, r, 200)

	if err != nil {
		return err

	}

	json.NewDecoder(status.Body).Decode(result)
	return nil

}

// GetEmail returns the first available email addres from the users attributes. Helper function
func (up UPResult) GetEmail() string {
	for _, attr := range up.Attributes {
		if (attr.Name == "email") && len(attr.Values) > 0 {
			return attr.Values[0]
		}
	}
	return ""
}
