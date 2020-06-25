package securityverify

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func get(c svProtocolClient, path string, expected int) (*http.Response, error) {

	url := fmt.Sprintf("https://%s%s", c.Tenant(), path)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}

	request, err = c.addAuthorization(request)
	if err != nil {
		log.Printf("Error in getting authorization: %s\n", err.Error())
		return nil, err
	}

	// Optionally, call the decorator
	if d, ok := c.(DecoratedClient); ok {
		request = d.DecorateRequest(request)
	}
	log.Printf("Calling %s", url)

	result, err := c.client().Do(c.addAccepts(request))

	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}
	if result.StatusCode != expected {
		return nil, NewSVError(result, expected)
	}
	return result, nil
}

func delete(c svProtocolClient, path string, expected int) (*http.Response, error) {

	url := fmt.Sprintf("https://%s%s", c.Tenant(), path)
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}
	request, err = c.addAuthorization(request)
	if err != nil {
		log.Printf("Error in getting authorization: %s\n", err.Error())
		return nil, err
	}

	// Optionally, call the decorator
	if d, ok := c.(DecoratedClient); ok {
		request = d.DecorateRequest(request)
	}
	log.Printf("Calling %s", url)

	result, err := c.client().Do(c.addAccepts(request))

	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}
	if result.StatusCode != expected {
		return nil, NewSVError(result, expected)
	}
	return result, nil
}

func post(c svProtocolClient, path string, body io.Reader, expected int) (*http.Response, error) {
	url := fmt.Sprintf("https://%s%s", c.Tenant(), path)
	request, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}

	request, err = c.addAuthorization(request)
	if err != nil {
		log.Printf("Error in getting authorization: %s\n", err.Error())
		return nil, err
	}

	request = c.addContentType(c.addAccepts(request))

	// Optionally, call the decorator
	if d, ok := c.(DecoratedClient); ok {
		request = d.DecorateRequest(request)
	}
	log.Printf("Calling %s", url)

	result, err := c.client().Do(request)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, err.Error())
		return nil, err
	}

	if result.StatusCode != expected {
		return nil, NewSVError(result, expected)
	}

	return result, nil
}
