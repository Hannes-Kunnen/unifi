package unifi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// FirewallGroupResponse is the representation of a response of a firewall group request
type FirewallGroupResponse struct {
	Meta Meta                        `json:"meta"`
	Data []FirewallGroupResponseData `json:"data"`
}

// FirewallGroupResponseData is the representation of the data inside the data array of the
// FirewallGroupResponse
type FirewallGroupResponseData struct {
	FirewallGroup
	DataValidationError
}

// FirewallGroup is the representation of a firewall group
type FirewallGroup struct {
	// The group data
	GroupMembers []string `json:"group_members,omitempty"`
	// The group name
	Name string `json:"name,omitempty"`
	// The ID of the site this group is linked to
	SiteId string `json:"site_id,omitempty"`
	// The group ID
	Id string `json:"_id,omitempty"`
	// The type of group, options:
	//	- address-group: Contains IPv4 addresses
	//	- ipv6-address-group: Contains IPv6 addresses
	//	- port-group: Contains port(s) and/or port range(s)
	GroupType string `json:"group_type,omitempty"`
}

// CreateFirewallGroup creates a new firewall group linked to this Site
func (site *Site) CreateFirewallGroup(
	// The data of the new group
	newGroupData FirewallGroup,
) (responseData FirewallGroupResponse, err error) {
	err = site.controller.verifyAuthentication()
	if err != nil {
		return
	}

	byteArray, err := json.Marshal(newGroupData)
	if err != nil {
		return
	}

	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")
	payload := bytes.NewBuffer(byteArray)
	req, err := http.NewRequest(`POST`, endpointUrl, payload)
	if err != nil {
		return
	}

	site.controller.AuthorizeRequest(req)
	req.Header.Set("Content-Type", "application/json")

	res, err := site.controller.httpClient.Do(req)
	if err != nil {
		return
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("creating firewall group failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetAllFirewallGroups returns all firewall groups linked to this Site
func (site *Site) GetAllFirewallGroups() (responseData FirewallGroupResponse, err error) {
	err = site.controller.verifyAuthentication()
	if err != nil {
		return
	}

	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")
	req, err := http.NewRequest(`GET`, endpointUrl, nil)
	if err != nil {
		return
	}

	site.controller.AuthorizeRequest(req)

	res, err := site.controller.httpClient.Do(req)
	if err != nil {
		return
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall groups failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetFirewallGroup returns the firewall group linked to the given ID and this Site
func (site *Site) GetFirewallGroup(
	// The firewall group ID
	id string,
) (responseData FirewallGroupResponse, err error) {
	err = site.controller.verifyAuthentication()
	if err != nil {
		return
	}

	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	req, err := http.NewRequest(`GET`, endpointUrl, nil)
	if err != nil {
		return
	}

	site.controller.AuthorizeRequest(req)

	res, err := site.controller.httpClient.Do(req)
	if err != nil {
		return
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall group failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// UpdateFirewallGroup updates the firewall group linked to the given ID and this Site
func (site *Site) UpdateFirewallGroup(
	// The firewall group ID
	id string,
	// The updated group data
	newGroupData FirewallGroup,
) (responseData FirewallGroupResponse, err error) {
	err = site.controller.verifyAuthentication()
	if err != nil {
		return
	}

	byteArray, err := json.Marshal(newGroupData)
	if err != nil {
		return
	}

	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	payload := bytes.NewBuffer(byteArray)
	req, err := http.NewRequest(`PUT`, endpointUrl, payload)
	if err != nil {
		return
	}

	site.controller.AuthorizeRequest(req)
	req.Header.Set("Content-Type", "application/json")

	res, err := site.controller.httpClient.Do(req)
	if err != nil {
		return
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("firewall group update failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// DeleteFirewallGroup deletes the firewall group linked to the given ID and this Site
func (site *Site) DeleteFirewallGroup(
	// The firewall group ID
	id string,
) (responseData FirewallGroupResponse, err error) {
	err = site.controller.verifyAuthentication()
	if err != nil {
		return
	}

	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	req, err := http.NewRequest(`DELETE`, endpointUrl, nil)
	if err != nil {
		return
	}

	site.controller.AuthorizeRequest(req)

	res, err := site.controller.httpClient.Do(req)
	if err != nil {
		return
	}

	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(res.Body)

	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("deleting firewall group failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}
