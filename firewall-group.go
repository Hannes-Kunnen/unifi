package unifi

import (
	"errors"
	"fmt"
	"net/http"
)

// FirewallGroupResponse is the representation of a response of a firewall group request.
type FirewallGroupResponse struct {
	Meta Meta                        `json:"meta"`
	Data []FirewallGroupResponseData `json:"data"`
}

// FirewallGroupResponseData is the representation of the data inside the data array of the
// FirewallGroupResponse.
type FirewallGroupResponseData struct {
	FirewallGroup
	DataValidationError
}

// FirewallGroup is the representation of a firewall group.
type FirewallGroup struct {
	// The group data.
	GroupMembers []string `json:"group_members,omitempty"`
	// The group name.
	Name string `json:"name,omitempty"`
	// The ID of the site this group is linked to.
	SiteId string `json:"site_id,omitempty"`
	// The group ID.
	Id string `json:"_id,omitempty"`
	// The type of group, options:
	//	- address-group: Contains IPv4 addresses.
	//	- ipv6-address-group: Contains IPv6 addresses.
	//	- port-group: Contains port(s) and/or port range(s).
	GroupType string `json:"group_type,omitempty"`
}

// CreateFirewallGroup creates a new firewall group linked to this Site.
func (site *Site) CreateFirewallGroup(
	// The data of the new group.
	firewallGroup FirewallGroup,
) (FirewallGroupResponse, error) {
	responseData := FirewallGroupResponse{}
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")

	res, err := site.controller.execute(http.MethodPost, endpointUrl, firewallGroup, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("creating firewall group failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetAllFirewallGroups returns all firewall groups linked to this Site.
func (site *Site) GetAllFirewallGroups() (FirewallGroupResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")
	responseData := FirewallGroupResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall groups failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetFirewallGroup returns the firewall group linked to the given ID and this Site.
func (site *Site) GetFirewallGroup(
	// The firewall group ID.
	id string,
) (FirewallGroupResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	responseData := FirewallGroupResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall group failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// UpdateFirewallGroup updates the firewall group linked to the given ID and this Site.
func (site *Site) UpdateFirewallGroup(
	// The firewall group ID.
	id string,
	// The updated group data.
	firewallGroup FirewallGroup,
) (FirewallGroupResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	responseData := FirewallGroupResponse{}

	res, err := site.controller.execute(http.MethodPut, endpointUrl, firewallGroup, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("firewall group update failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// DeleteFirewallGroup deletes the firewall group linked to the given ID and this Site.
func (site *Site) DeleteFirewallGroup(
	// The firewall group ID.
	id string,
) (FirewallGroupResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)
	responseData := FirewallGroupResponse{}

	res, err := site.controller.execute(http.MethodDelete, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("deleting firewall group failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}
