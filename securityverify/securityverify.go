package securityverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/yaml.v2"
)

func ReadEnvYaml(path string) (*SVEnv, error) {

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	result := &SVEnv{}
	err = yaml.NewDecoder(file).Decode(result)

	if err != nil {
		return nil, err
	}

	validate := validator.New()

	err = validate.Struct(result)
	if err != nil {

		return nil, err

	}

	return result, nil

}

type SVEnv struct {
	TenantId     string `yaml:"tenant" json:"tenant" validate:"required"`
	ClientId     string `yaml:"client_id" json:"client_id" validate:"required"`
	ClientSecret string `yaml:"client_secret" json:"client_secret" validate:"required"`
}

type SVError struct {
	Id          string `json:"messageId" validator:"required"`
	Description string `json:"messageDescription"`
}

func (sve SVError) Error() error {
	return fmt.Errorf("%s: %s", sve.Id, sve.Description)
}

type SVClient struct {
	http.Client
	*SVAPIClient
}

func NewSVClient(env *SVEnv) *SVClient {
	return &SVClient{
		SVAPIClient: NewSVAPIClient(env.ClientId, env.ClientSecret, env.TenantId)}

}

func NewSVError(response *http.Response) *SVError {

	things, _ := ioutil.ReadAll(response.Body)

	fmt.Print("stuff: %s", string(things))
	svError := &SVError{}
	json.NewDecoder(bytes.NewBuffer(things)).Decode(svError)
	return svError
}
