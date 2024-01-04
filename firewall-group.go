package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type FirewallGroupResponse struct {
	Meta Meta            `json:"meta"`
	Data []FirewallGroup `json:"data"`
}

type FirewallGroup struct {
	GroupMembers []string `json:"group_members"`        // The group data (e.g. IPv6 addresses)
	Name         string   `json:"name,omitempty"`       // The group name
	SiteId       string   `json:"site_id,omitempty"`    // The id of the site linked to this group
	Id           string   `json:"_id,omitempty"`        // The group ID
	GroupType    string   `json:"group_type,omitempty"` // The type of group
}

// CreateFirewallGroup creates a new firewall group linked to this site
func (site *Site) CreateFirewallGroup(
	newGroupData FirewallGroup, // The data of the new group
) (responseData FirewallGroupResponse, err error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: site.Controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   site.Controller.RequestTimeout,
		Transport: transport,
	}

	byteArray, err := json.Marshal(newGroupData)
	if err != nil {
		return
	}

	payload := bytes.NewBuffer(byteArray)

	req, err := http.NewRequest(`POST`, endpointUrl, payload)
	if err != nil {
		return
	}

	// Add authentication
	req.AddCookie(site.Controller.cookie)
	req.Header.Set("X-CSRF-Token", site.Controller.csrfToken)

	res, err := client.Do(req)
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

// GetAllFirewallGroups returns all firewall groups linked to this site
func (site *Site) GetAllFirewallGroups() (responseData FirewallGroupResponse, err error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", "")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: site.Controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   site.Controller.RequestTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(`GET`, endpointUrl, nil)
	if err != nil {
		return
	}

	// Add authentication
	req.AddCookie(site.Controller.cookie)
	req.Header.Set("X-CSRF-Token", site.Controller.csrfToken)

	res, err := client.Do(req)
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

// GetFirewallGroup returns the firewall group linked to the given ID from this site
func (site *Site) GetFirewallGroup(id string) (responseData FirewallGroupResponse, err error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: site.Controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   site.Controller.RequestTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(`GET`, endpointUrl, nil)
	if err != nil {
		return
	}

	// Add authentication
	req.AddCookie(site.Controller.cookie)
	req.Header.Set("X-CSRF-Token", site.Controller.csrfToken)

	res, err := client.Do(req)
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

// UpdateFirewallGroup updates the firewall group linked to this site with the given ID
func (site *Site) UpdateFirewallGroup(
	id string, // The firewall group id
	newGroupData FirewallGroup, // The updated group data
) (responseData FirewallGroupResponse, err error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: site.Controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   site.Controller.RequestTimeout,
		Transport: transport,
	}

	byteArray, err := json.Marshal(newGroupData)
	if err != nil {
		return
	}

	payload := bytes.NewBuffer(byteArray)

	req, err := http.NewRequest(`PUT`, endpointUrl, payload)
	if err != nil {
		return
	}

	// Add authentication
	req.AddCookie(site.Controller.cookie)
	req.Header.Set("X-CSRF-Token", site.Controller.csrfToken)

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
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

// DeleteFirewallGroup deletes the firewall group linked to the given ID from this site
func (site *Site) DeleteFirewallGroup(id string) (responseData FirewallGroupResponse, err error) {
	endpointUrl := site.createEndpointUrl("rest/firewallgroup", id)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: site.Controller.SkipTLSVerification},
	}

	client := &http.Client{
		Timeout:   site.Controller.RequestTimeout,
		Transport: transport,
	}

	req, err := http.NewRequest(`DELETE`, endpointUrl, nil)
	if err != nil {
		return
	}

	// Add authentication
	req.AddCookie(site.Controller.cookie)
	req.Header.Set("X-CSRF-Token", site.Controller.csrfToken)

	res, err := client.Do(req)
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
