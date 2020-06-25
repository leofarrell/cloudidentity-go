package securityverify

import (
	"encoding/json"
	"log"
)

// IdentitySource as it is defined.
type IdentitySource struct {
	Status            string                        `json:"status"`
	Predefined        bool                          `json:"predefined"`
	SourceTypeID      int                           `json:"sourceTypeId"`
	AttributeMappings map[string]*json.RawMessage   `json:"attributeMappings"`
	Enabled           bool                          `json:"enabled"`
	InstanceName      string                        `json:"instanceName"`
	Properties        []map[string]*json.RawMessage `json:"properties"`
	ID                string                        `json:"id"`
}

// GetIdentitySources configured
// See: https://myidp.ice.ibmcloud.com/developer/explorer/#!/Identity_Sources/getInstances
func (sv *SVJSONClient) GetIdentitySources() ([]IdentitySource, error) {

	rsp, err := get(sv, urlIdentitySources, 200)
	if err != nil {
		log.Printf("Err: %s", err.Error())
		return nil, err
	}

	result := struct {
		IdentitySources []IdentitySource `json:"identitySources"`
	}{}
	json.NewDecoder(rsp.Body).Decode(&result)

	return result.IdentitySources, nil
}

// GetCloudDirectoryIdentitySource returns the identity source matcing the name 'Cloud Directory'
func (sv *SVJSONClient) GetCloudDirectoryIdentitySource() (string, error) {

	srcs, err := sv.GetIdentitySources()

	if err != nil {
		return "", err
	}

	for _, src := range srcs {
		if src.InstanceName == constCloudDirectory {
			return src.ID, nil
		}
	}

	return "", nil
}
