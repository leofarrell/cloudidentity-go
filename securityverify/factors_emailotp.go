package securityverify

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
)

// EmailOtpEnrollment for a given user
type EmailOtpEnrollment struct {
	FactorsEnrollment
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
