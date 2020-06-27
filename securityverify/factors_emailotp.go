package securityverify

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
)

// EmailOtpEnrollment for a given user
type EmailOtpEnrollment struct {
	factorsEnrollment
	Email   string `json:"email"`
	Enabled bool   `json:"enabled"`
}

//EnrollEmailOtp using the provided userID and email address. Doesn't impact any existing enrollments
func (f *FactorsClient) EnrollEmailOtp(userID, email string) (*EmailOtpEnrollment, error) {

	r := outputPipe(&struct {
		Email   string `json:"emailAddress"`
		Enabled bool   `json:"enabled"`
		UserID  string `json:"userId"`
	}{UserID: userID, Enabled: true, Email: email})

	rsp, err := post(f.client, urlFactorsEmailotp, r, 201)
	if err != nil {
		return nil, err
	}

	structure := &EmailOtpEnrollment{}
	err = json.NewDecoder(rsp.Body).Decode(&structure)
	if err != nil {
		return nil, err
	}

	return structure, nil

}

// GetEmailOtpEnrollmentsForUser belonging to a give userID
func (f *FactorsClient) GetEmailOtpEnrollmentsForUser(userID string) ([]EmailOtpEnrollment, error) {
	return f.GetEmailOtpEnrollments(fmt.Sprintf(`userId = "%s"`, userID))
}

// GetEmailOtpEnrollments belonging to a give userID
// See: https://myidp.ice.ibmcloud.com/developer/explorer/#!/Email_One-time_Password_2.0/listEmailotpEnrollments_2_0
func (f *FactorsClient) GetEmailOtpEnrollments(search string) ([]EmailOtpEnrollment, error) {
	qs := url.Values{}

	if search != "" {
		qs.Add("search", search)
	}

	url := fmt.Sprintf("%s?%s", urlFactorsEmailotp, qs.Encode())

	rsp, err := get(f.client, url, 200)
	if err != nil {
		return nil, err
	}

	structure := struct {
		EmailOTP []EmailOtpEnrollment `json:"emailotp"`
		Count    int
	}{}

	log.Print("Found ", structure.Count)
	log.Print("Found ", structure.EmailOTP)

	err = json.NewDecoder(rsp.Body).Decode(&structure)
	if err != nil {
		return nil, err
	}

	return structure.EmailOTP, nil
}

// EmailOtpVerification structure from initaion
type EmailOtpVerification struct {
	factorsBase
	State        string `json:"state"`
	EmailAddress string `json:"emailAddress"`
	Correlation  string `json:"correlation"`
	EnrollmentID string `json:"-"`
}

//InitiateEmailOtp for a given enrollment
func (f *FactorsClient) InitiateEmailOtp(enrollment string, emailOtpHint string, output *EmailOtpVerification) error {
	r := outputPipe(&struct {
		Correlation string `json:"correlation"`
	}{Correlation: emailOtpHint})
	response, err := post(f.client, fmt.Sprintf("%s/%s/%s", urlFactorsEmailotp, enrollment, constVerifications), r, 201)
	if err != nil {
		return err
	}

	err = json.NewDecoder(response.Body).Decode(output)
	if err != nil {
		return err
	}

	output.EnrollmentID = enrollment
	return nil
}

// ValidateEmailOtp presents the provided email otp to a enrollment and transaction
// See: https://myidp.ice.ibmcloud.com/developer/explorer/#!/Email_One-time_Password_2.0/attemptEmailotpVerification_2_0
func (f *FactorsClient) ValidateEmailOtp(otp, enrollmentID, transactionID string, returnJwt bool) (string, error) {
	r := outputPipe(&struct {
		OTP string `json:"otp"`
	}{OTP: otp})

	expected := 204
	if returnJwt {
		expected = 200
	}
	response, err := post(f.client, fmt.Sprintf("%s/%s/%s/%s?returnJwt=%s", urlFactorsEmailotp, enrollmentID, constVerifications, transactionID, strconv.FormatBool(returnJwt)), r, expected)
	if err != nil {
		return "", err
	}

	asst := ""
	if returnJwt {
		asstBody := &factorsAssertion{}
		err := json.NewDecoder(response.Body).Decode(asstBody)
		if err != nil {
			return "", err
		}
		asst = asstBody.Assertion
	}
	return asst, nil

}
