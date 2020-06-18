package securityverify

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	CONTENT_JSON = "application/json"
)

func traceBody(result *http.Response) {
	if result != nil {
		body, berr := ioutil.ReadAll(result.Body)
		if berr != nil {
			log.Printf("Error parsing body")
		} else {
			log.Printf("Error response body: \n----\n%s\n----\n", body)
		}
	}
}

func structToJson(obj interface{}) (io.Reader, error) {

	jb, err := json.Marshal(obj)

	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(jb), nil
}
