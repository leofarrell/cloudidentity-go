package securityverify

const (
	USERNAME_PASSWORD = "/v1.0/authnmethods/password/"
)

type UP struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *SVClient) UsernamePassword(username, password, identitysource string) (bool, error) {

	up := UP{Username: username, Password: password}

	jsonStream, err := structToJson(up)

	if err != nil {
		return false, err
	}

	status, svError, err := c.Post(USERNAME_PASSWORD, CONTENT_JSON, jsonStream, 204)

	if err != nil {
		return false, err
	}
	if svError != nil {
		return false, svError.Error()
	}

	return status.StatusCode == 204, nil

}
