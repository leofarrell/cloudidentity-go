package securityverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
)

const (
	USERS       = "/v2.0/Users"
	SCIM        = "application/scim+json"
	USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
)

type TypeValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Name struct {
	FirstName string `json:"firstName,omitempty"` // TODO the other 3
}

type User struct {
	UserName    string      `json:"userName"`
	Emails      []TypeValue `json:"emails"`
	Name        *Name       `json:"name,omitempty"`
	DisplayName string      `json:"displayName"`

	PhoneNumbers []TypeValue `json:"phoneNumbers,omitempty"`

	Active  bool     `json:"active"`
	Schemas []string `json:"schemas"`
	ID      string   `json:"id"`

	Password string `json:"password,omitempty"`
}

type ScimSearch struct {
	Resources []User `json:"Resources"`
	Total     int    `json:"totalResults"`
}

func (c *SVClient) ListUser() []User {

	result, svError, err := c.Get(USERS, 200)
	if err != nil {
		log.Fatal(err)
	}
	if svError != nil {
		log.Fatal(svError.Error())
	}

	built := &ScimSearch{}

	err = json.NewDecoder(result.Body).Decode(built)
	if err != nil {
		log.Fatal(err)
	}

	return built.Resources
}

func (c *SVClient) FindUser(userName string) *User {

	values := url.Values{}

	values.Add("filter", fmt.Sprintf("username eq \"%s\"", userName))
	url := fmt.Sprintf("%s?%s", USERS, values.Encode())
	log.Print(url)
	result, svError, err := c.Get(url, 200)
	if err != nil {
		log.Fatal(err)
	}
	if svError != nil {
		log.Fatal(svError.Error())
	}

	log.Print(result.StatusCode)

	built := &ScimSearch{}

	err = json.NewDecoder(result.Body).Decode(built)
	if err != nil {
		log.Fatal(err)
	}

	if built.Total < 1 {
		return nil
	}

	log.Printf("Search result: %+v", built)

	return &built.Resources[0]
}

func (c *SVClient) CreateUser(user User) (*User, error) {
	user.Schemas = []string{USER_SCHEMA}
	log.Printf("Encode")

	encoded, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}
	log.Printf("Posting %s", string(encoded))
	result, svError, err := c.Post(USERS, SCIM, bytes.NewReader(encoded), 201)
	if err != nil {
		return nil, err
	}
	if svError != nil {
		return nil, svError.Error()
	}
	resultUser := &User{}
	json.NewDecoder(result.Body).Decode(resultUser)
	log.Print("Create user result ", resultUser)
	return resultUser, nil
}
