package securityverify

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func (c *SVClient) Get(path string, expected int) (*http.Response, *SVError, error) {

	url := fmt.Sprintf("https://%s%s", c.tenantId, path)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}
	request.Header.Add("authorization", fmt.Sprintf("bearer %s", c.Token()))

	result, err := c.Do(request)

	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}
	if result.StatusCode != expected {
		return nil, NewSVError(result), nil

	}
	return result, nil, nil
}

func (c *SVClient) Delete(path string, expected int) (*http.Response, *SVError, error) {

	url := fmt.Sprintf("https://%s%s", c.tenantId, path)
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}
	request.Header.Add("authorization", fmt.Sprintf("bearer %s", c.Token()))

	result, err := c.Do(request)

	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}
	if result.StatusCode != expected {
		return nil, NewSVError(result), nil
	}
	return result, nil, nil
}

func (c *SVClient) Post(path string, contentType string, body io.Reader, expected int) (*http.Response, *SVError, error) {
	url := fmt.Sprintf("https://%s%s", c.tenantId, path)
	request, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}
	request.Header.Add("authorization", fmt.Sprintf("bearer %s", c.Token()))
	request.Header.Add("content-type", contentType)

	result, err := c.Do(request)
	if err != nil {
		log.Printf("Error calling [%s]: %s\n", url, error.Error)
		return nil, nil, err
	}

	if result.StatusCode != expected {
		fmt.Printf("Unexpected status %d, wanted %d\n", result.StatusCode, expected)
		return nil, NewSVError(result), nil
	}

	return result, nil, nil
}
