package unifi

import (
	"errors"
	"fmt"
	"net/http"
)

// FirewallRuleResponse is the representation of a response of a firewall rule request
type FirewallRuleResponse struct {
	Meta Meta                       `json:"meta"`
	Data []FirewallRuleResponseData `json:"data"`
}

// FirewallRuleResponseData is the representation of the data inside the data array of the
// FirewallRuleResponse
type FirewallRuleResponseData struct {
	FirewallRule
	DataValidationError
}

// FirewallRule is the representation of a firewall rule
type FirewallRule struct {
	// The rule ID
	Id string `json:"_id,omitempty"`
	// The ID of the site linked to this rule
	SiteId string `json:"site_id,omitempty"`
	// The rule index (lower index is processed first)
	RuleIndex int `json:"rule_index,omitempty"`
	// Indicates whether the rule is enabled
	Enabled bool `json:"enabled,omitempty"`
	// Determines in which direction and on which network the firewall rule is applied, options:
	//	- WAN_IN: IPv4 traffic coming from a WAN network, destined for other networks
	//	- WAN_OUT: IPv4 traffic coming other networks, destined for a WAN network
	//	- WAN_LOCAL: IPv4 traffic coming from a WAN network, destined for the UDM/USG
	//	- LAN_IN: IPv4 traffic coming from a LAN network, destined for other networks
	//	- LAN_OUT: IPv4 traffic coming other networks, destined for a LAN network
	//	- LAN_LOCAL: IPv4 traffic coming from a LAN network, destined for the UDM/USG
	//	- GUEST_IN: IPv4 traffic coming from a guest network, destined for other networks
	//	- GUEST_OUT: IPv4 traffic coming other networks, destined for a guest network
	//	- GUEST_LOCAL: IPv4 traffic coming from a guest network, destined for the UDM/USG
	//	- WANv6_IN: IPv6 traffic coming from a WAN network, destined for other networks
	//	- WANv6_OUT: IPv6 traffic coming other networks, destined for a WAN network
	//	- WANv6_LOCAL: IPv6 traffic coming from a WAN network, destined for the UDM/USG
	//	- LANv6_IN: IPv6 traffic coming from a LAN network, destined for other networks
	//	- LANv6_OUT: IPv6 traffic coming other networks, destined for a LAN network
	//	- LANv6_LOCAL: IPv6 traffic coming from a LAN network, destined for the UDM/USG
	//	- GUESTv6_IN: IPv6 traffic coming from a guest network, destined for other networks
	//	- GUESTv6_OUT: IPv6 traffic coming other networks, destined for a guest network
	//	- GUESTv6_LOCAL: IPv6 traffic coming from a guest network, destined for the UDM/USG
	Ruleset string `json:"ruleset,omitempty"`
	// The name of the rule
	Name string `json:"name,omitempty"`
	// What action the rule should take, options:
	//	- accept: The traffic is allowed
	//	- reject: The traffic is dropped and a response is sent back to the source
	//	- drop: The traffic is dropped and no response is sent back
	Action string `json:"action,omitempty"`
	// The protocol (IPv4) on which to apply this rule, options:
	//	- all, tcp, udp, tcp_udp, icmp, ah, ax.25, dccp, ddp, egp, eigrp, encap, esp, etherip, fc,
	//		ggp, gre, hip, hmp, idpr-cmtp, idrp, igmp, igp, ip, ipcomp, ipencap, ipip, ipv6,
	//		ipv6-frag, ipv6-icmp, ipv6-nonxt, ipv6-opts, ipv6-route, isis, iso-tp4, l2tp, manet,
	//		mobility-header, mpls-in-ip, ospf, pim, pup, rdp, rohc, rspf, rsvp, sctp, shim6, skip,
	//		st, udplite, vmtp, vrrp, wesp, xns-idp, xtp
	//	- A protocol number can also be used
	Protocol string `json:"protocol,omitempty"`
	// The protocol (IPv6) on which to apply this rule, options:
	//	- all, tcp, udp, tcp_udp, icmp, ah, ax.25, dccp, ddp, egp, eigrp, encap, esp, etherip, fc,
	//		ggp, gre, hip, hmp, idpr-cmtp, idrp, igmp, igp, ip, ipcomp, ipencap, ipip, ipv6,
	//		ipv6-frag, ipv6-icmp, ipv6-nonxt, ipv6-opts, ipv6-route, isis, iso-tp4, l2tp, manet,
	//		mobility-header, mpls-in-ip, ospf, pim, pup, rdp, rohc, rspf, rsvp, sctp, shim6, skip,
	//		st, udplite, vmtp, vrrp, wesp, xns-idp, xtp
	//	- A protocol number can also be used
	ProtocolV6 string `json:"protocol_v6,omitempty"`
	// Matches all protocols except the chosen protocol
	ProtocolMatchExcepted bool `json:"protocol_match_excepted,omitempty"`
	// Source address and/or port group(s) (IPv4 source type: 'Port/IP Group' or IPv6 rule)
	SrcFirewallGroupIds []string `json:"src_firewallgroup_ids,omitempty"`
	// Source network ID (IPv4 source type: 'Network')
	SrcNetworkConfId string `json:"src_networkconf_id,omitempty"`
	// Source network config type (IPv4), options:
	//	- ADDRv4
	//	- NETv4
	SrcNetworkConfType string `json:"src_networkconf_type,omitempty"`
	// Source address (IPv4 source type: 'IP Address')
	SrcAddress string `json:"src_address,omitempty"`
	// Source port(s) and/or port range(s) (comma separated) (IPv4 source type: 'IP Address')
	SrcPort string `json:"src_port,omitempty"`
	// Source MAC address
	SrcMacAddress string `json:"src_mac_address,omitempty"`
	// Destination address and/or port group(s)
	// (IPv4 destination type: 'Port/IP Group' or IPv6 rule)
	DstFirewallGroupIds []string `json:"dst_firewallgroup_ids,omitempty"`
	// Destination network ID (IPv4 destination type: 'Network')
	DstNetworkConfId string `json:"dst_networkconf_id,omitempty"`
	// Destination network config type (IPv4), options:
	//	- ADDRv4
	//	- NETv4
	DstNetworkConfType string `json:"dst_networkconf_type,omitempty"`
	// Destination address (IPv4 destination type: 'IP Address')
	DstAddress string `json:"dst_address,omitempty"`
	// Destination port(s) and/or port range(s) (comma separated)
	// (IPv4 destination type: 'IP Address')
	DstPort string `json:"dst_port,omitempty"`
	// Indicates how advanced settings should be applied, options:
	//	- auto: Overrides advanced settings and sets them automatically
	//	- manual: Advanced settings have to be set by the user
	SettingPreference string `json:"setting_preference,omitempty"`
	// Match traffic state new (if all states are false they are ignored)
	StateNew bool `json:"state_new,omitempty"`
	// Match traffic state invalid (if all states are false they are ignored)
	StateInvalid bool `json:"state_invalid,omitempty"`
	// Match traffic state established (if all states are false they are ignored)
	StateEstablished bool `json:"state_established,omitempty"`
	// Match traffic state related (if all states are false they are ignored)
	StateRelated bool `json:"state_related,omitempty"`
	// IPsec rule matching settings, options:
	//	- (empty): Matches all traffic and not specifically IPsec or non-IPsec traffic (default)
	//	- match-ipsec: Match traffic that is encrypted by IPsec
	//	- match-none: Match specifically on unencrypted traffic
	Ipsec string `json:"ipsec,omitempty"`
	// Generates a syslog entry when this firewall rule is matched
	Logging bool `json:"logging,omitempty"`
	// Use case unknown
	ICMPTypename string `json:"icmp_typename,omitempty"`
	// Use case unknown
	ICMPv6Typename string `json:"icmpv6_typename,omitempty"`
}

// CreateFirewallRule creates a new firewall rule linked to this Site
func (site *Site) CreateFirewallRule(
	// The data of the new rule
	firewallRule FirewallRule,
) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", "")
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodPost, endpointUrl, firewallRule, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("creating firewall rule failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetAllFirewallRules returns all firewall rules linked to this Site
func (site *Site) GetAllFirewallRules() (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", "")
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall rules failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetFirewallRule returns the firewall rule linked to the given ID and this Site
func (site *Site) GetFirewallRule(
	// The firewall rule ID
	id string,
) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", id)
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall rule failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// UpdateFirewallRule updates the firewall rule linked to the given ID and this Site
func (site *Site) UpdateFirewallRule(
	// The firewall rule ID
	id string,
	// The updated rule data
	firewallRule FirewallRule,
) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", id)
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodPut, endpointUrl, firewallRule, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("firewall rule update failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}

// DeleteFirewallRule deletes the firewall rule linked to the given ID and this Site
func (site *Site) DeleteFirewallRule(
	// The firewall rule ID
	id string,
) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", id)
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodDelete, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("deleting firewall rule failed with response code %d\n", res.StatusCode),
		)
	}

	return responseData, nil
}
