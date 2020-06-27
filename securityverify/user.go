package securityverify

import (
	"encoding/json"
	"fmt"
	"net/url"
)

//User provides calls to the user APIs.
// See:https://myidp.ice.ibmcloud.com/developer/explorer/#/Users_Management_Version_2.0
func (c *SVAPIClient) User() *UserClient {
	return &UserClient{client: newSVSCIMClient(c)}
}

//User provides calls to the user APIs.
// See:https://myidp.ice.ibmcloud.com/developer/explorer/#/Users_Management_Version_2.0
func (c *BearerToken) User() *UserClient {
	return &UserClient{client: newSVSCIMClient(c)}
}

// UserClient contains API calls to the Security Verify users API
// See:https://myidp.ice.ibmcloud.com/developer/explorer/#/Users_Management_Version_2.0
type UserClient struct {
	client *svSCIMClient
}

// TypeValue is a structure containing a type and its value
type TypeValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type name struct {
	FirstName string `json:"firstName,omitempty"` // TODO: the other 3
}

// User structure
type User struct {
	UserName    string      `json:"userName"`
	Emails      []TypeValue `json:"emails"`
	Name        *name       `json:"name,omitempty"`
	DisplayName string      `json:"displayName"`

	PhoneNumbers []TypeValue `json:"phoneNumbers,omitempty"`

	Active  bool     `json:"active"`
	Schemas []string `json:"schemas"`
	ID      string   `json:"id"`

	Password string `json:"password,omitempty"`
}

// ListUsers matching a filter
// See https://myidp.ice.ibmcloud.com/developer/explorer/#!/Users_Management_Version_2.0/getUsers
func (sv *UserClient) ListUsers(filter string) ([]User, error) {

	values := url.Values{}

	values.Add("filter", filter)
	url := fmt.Sprintf("%s?%s", urlUsers, values.Encode())
	result, err := get(sv.client, url, 200)
	if err != nil {
		return nil, err
	}

	built := &struct {
		Resources []User `json:"Resources"`
		Total     int    `json:"totalResults"`
	}{}

	err = json.NewDecoder(result.Body).Decode(built)
	if err != nil {
		return nil, err
	}

	return built.Resources, nil
}

// FindUser matching provided username
func (sv *UserClient) FindUser(userName string) (*User, error) {

	values := url.Values{}

	values.Add("filter", fmt.Sprintf("username eq \"%s\"", userName))

	result, err := sv.ListUsers(fmt.Sprintf("username eq \"%s\"", userName))
	if err != nil {
		return nil, err
	}

	svlog.Print("Find result:", result)

	if len(result) > 0 {
		return &result[0], nil
	}
	return nil, nil
}

// CreateUser using the provided profile structure
// See https://myidp.ice.ibmcloud.com/developer/explorer/#!/Users_Management_Version_2.0/createUser
func (sv *UserClient) CreateUser(user *User) (*User, error) {
	user.Schemas = []string{scimUserSchema}

	r := outputPipe(user)

	result, err := post(sv.client, urlUsers, r, 201)
	if err != nil {
		return nil, err
	}

	resultUser := &User{}
	json.NewDecoder(result.Body).Decode(resultUser)
	svlog.Print("Create user result ", resultUser)
	return resultUser, nil
}
