package securityverify

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SVAPIClient is a the encapsualtion of an API client used to call APIs
type SVAPIClient struct {
	tenantID     string
	clientID     string
	clientSecret string
	tokenLck     sync.Mutex
	token        string
	expires      time.Time
}

// NewSVAPIClient from creds and a tenant
func NewSVAPIClient(clientID, clientSecret, tenant string) *SVAPIClient {
	return &SVAPIClient{clientID: clientID,
		clientSecret: clientSecret,
		tokenLck:     sync.Mutex{},
		token:        "",
		expires:      time.Now(),
		tenantID:     tenant}
}

// Tenant invoked by this client
func (sv *SVAPIClient) Tenant() string {
	return sv.tenantID
}

// Token issued to this client
func (sv *SVAPIClient) Token() (string, error) {
	if sv.token == "" || sv.expires.Before(time.Now()) {
		sv.tokenLck.Lock()
		defer sv.tokenLck.Unlock()
		if sv.token == "" || sv.expires.Before(time.Now()) {
			sv.refresh()
		}

	}
	if sv.token == "" || sv.expires.Before(time.Now()) {
		err := sv.refresh()

		if err != nil {
			return "", err
		}
	}

	lifeLeft := sv.expires.Sub(time.Now())

	svlog.Printf("Token has %s to live", lifeLeft.String())

	// IDEA: use a goroutine to wake up near end of life and get a new token to avoid ever having any doing this refresh on a main thread

	return sv.token, nil
}

func (sv *SVAPIClient) refresh() error {

	if sv.clientSecret == "" {
		svlog.Printf("Warning, api client secret missing")
	}

	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", sv.clientID, sv.clientSecret)
	svlog.Print(strings.ReplaceAll(body, sv.clientSecret, "****"))
	url := fmt.Sprintf("https://%s%s", sv.tenantID, urlOidcToken)
	svlog.Print(url)
	request, err := http.NewRequest("POST", url,
		strings.NewReader(body))
	if err != nil {
		svlog.Print(err)
		return err
	}

	request.Header.Add("Content-type", "application/x-www-form-urlencoded")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	result, err := client.Do(request)
	if err != nil {
		svlog.Print(err)
		return err
	}
	if result.StatusCode != 200 {
		return fmt.Errorf("Unexpected status[%d]", result.StatusCode)
	}

	jsonData := make(map[string]interface{})

	json.NewDecoder(result.Body).Decode(&jsonData)

	if value, ok := jsonData["access_token"]; ok {
		sv.token = value.(string)
	}

	if value, ok := jsonData["expires_in"]; ok {
		sv.expires = time.Now().Add(time.Second * time.Duration(value.(float64)))
	}
	svlog.Printf("Token %s expires: %s", sv.token, sv.expires.String())
	return nil
}

func (sv *SVAPIClient) addAuthorization(req *http.Request) (*http.Request, error) {
	tkn, err := sv.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", tkn))
	return req, nil
}
