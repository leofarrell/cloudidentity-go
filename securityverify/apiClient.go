package securityverify

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SVAPIClient struct {
	tenantId     string
	clientID     string
	clientSecret string
	tokenLck     sync.Mutex
	token        string
	expires      time.Time
}

func NewSVAPIClient(clientID, clientSecret, tenantId string) *SVAPIClient {
	return &SVAPIClient{clientID: clientID,
		clientSecret: clientSecret,
		tokenLck:     sync.Mutex{},
		token:        "",
		expires:      time.Now(),
		tenantId:     tenantId}
}

func (t *SVAPIClient) Token() string {
	if t.token == "" || t.expires.Before(time.Now()) {
		t.tokenLck.Lock()
		defer t.tokenLck.Unlock()
		if t.token == "" || t.expires.Before(time.Now()) {
			t.refresh()
		}

	}
	if t.token == "" || t.expires.Before(time.Now()) {
		t.refresh()
	}

	lifeLeft := t.expires.Sub(time.Now())

	log.Printf("Token has %s to live", lifeLeft.String())
	return t.token
}

func (t *SVAPIClient) refresh() {

	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s", t.clientID, t.clientSecret)
	log.Print(body)
	url := fmt.Sprintf("https://%s/v1.0/endpoint/default/token", t.tenantId)
	log.Print(url)
	request, err := http.NewRequest("POST", url,
		strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}

	request.Header.Add("Content-type", "application/x-www-form-urlencoded")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	result, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	if result.StatusCode != 200 {
		log.Fatalf("Invalid response from ISV: %+v", result)
	}

	jsonData := make(map[string]interface{})

	json.NewDecoder(result.Body).Decode(&jsonData)

	if value, ok := jsonData["access_token"]; ok {
		t.token = value.(string)
	}

	if value, ok := jsonData["expires_in"]; ok {
		t.expires = time.Now().Add(time.Second * time.Duration(value.(float64)))
	}
	log.Printf("Token %s expires: %s", t.token, t.expires.String())
}
