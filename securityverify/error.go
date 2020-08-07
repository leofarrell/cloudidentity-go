package securityverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

// SVError structure, includes message code and human readable description
type SVError struct {
	ID          string `json:"messageId" validator:"required"`
	Description string `json:"messageDescription"`
}

func (sve SVError) Error() string {
	return fmt.Sprintf("%s: %s", sve.ID, sve.Description)
}

// NewSVError will parse an error from Security verify. Or if no error message is returned will indicate the unexpected status recieved
func NewSVError(response *http.Response, expected int) error {
	svError := &SVError{}
	var buf bytes.Buffer
	tee := io.TeeReader(response.Body, &buf)
	json.NewDecoder(tee).Decode(svError)

	// TODO some flag to turn extra verbose debug like this on/off.
	log.Println("Unexpected body:")
	erB, _ := ioutil.ReadAll(&buf)
	log.Println(string(erB))

	if svError.Description == "" {
		return fmt.Errorf("Unexpected HTTP status %d, wanted %d", response.StatusCode, expected)
	}
	return svError
}
