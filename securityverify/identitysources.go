package securityverify

import (
	"encoding/json"
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

type IdentitySourcesClient struct {
	client *svJSONClient
}

func (c *SVAPIClient) IdentitySources() *IdentitySourcesClient {
	return &IdentitySourcesClient{client: newSVJSONClient(c)}
}

// GetIdentitySources configured
// See: https://myidp.ice.ibmcloud.com/developer/explorer/#!/Identity_Sources/getInstances
func (sv *IdentitySourcesClient) GetIdentitySources() ([]IdentitySource, error) {

	rsp, err := get(sv.client, urlIdentitySources, 200)
	if err != nil {
		svlog.Printf("Err: %s", err.Error())
		return nil, err
	}

	result := struct {
		IdentitySources []IdentitySource `json:"identitySources"`
	}{}
	json.NewDecoder(rsp.Body).Decode(&result)

	return result.IdentitySources, nil
}

// GetCloudDirectoryIdentitySource returns the identity source matcing the name 'Cloud Directory'
func (sv *IdentitySourcesClient) GetCloudDirectoryIdentitySource() (string, error) {

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
