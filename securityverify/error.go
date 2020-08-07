package securityverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// TODO some flag to turn extra verbose debug like this on/off.
var verbose = true

// OIDCError
type OIDCError struct {
	OIDCID          string `json:"error"`
	OIDCDescription string `json:"error_description"`
}

// intSVError is the internal error structer, which gets normalized into the SVError structure
type intSVError struct {
	// Standard errors
	SVError
	// OIDC / OAuth 2.0 errors
	OIDCError
}

type SVError struct {
	ID          string `json:"messageId"`
	Description string `json:"messageDescription"`
}

func (sve SVError) Error() string {
	return fmt.Sprintf("%s: %s", sve.ID, sve.Description)
}

// NewSVError will parse an error from Security verify. Or if no error message is returned will indicate the unexpected status recieved
func NewSVError(response *http.Response, expected int) error {

	// Internal error
	intSvError := &intSVError{}
	var buf bytes.Buffer
	tee := io.TeeReader(response.Body, &buf)
	json.NewDecoder(tee).Decode(intSvError)

	if verbose {
		svlog.Println("Unexpected body:")
		erB, _ := ioutil.ReadAll(&buf)
		svlog.Println(string(erB))
	}

	svError := &SVError{}

	// map different errors into standard fields
	if intSvError.ID == "" && intSvError.Description == "" && (intSvError.OIDCID != "" || intSvError.OIDCDescription != "") {
		svError.ID = intSvError.OIDCID
		svError.Description = intSvError.OIDCDescription
	} else {
		svError.ID = intSvError.ID
		svError.Description = intSvError.Description
	}

	if svError.Description == "" {
		return fmt.Errorf("Unexpected HTTP status %d, wanted %d", response.StatusCode, expected)
	}
	return svError
}
