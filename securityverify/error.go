package securityverify

import (
	"encoding/json"
	"fmt"
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

// NewSVError will parse an error from Security verify. Or of no error message is returned will indicate the unexpected status recieved
func NewSVError(response *http.Response, expected int) error {
	svError := &SVError{}
	json.NewDecoder(response.Body).Decode(svError)

	if svError.Description == "" {
		return fmt.Errorf("Unexpected HTTP status %d, wanted %d", response.StatusCode, expected)
	}
	return svError
}
