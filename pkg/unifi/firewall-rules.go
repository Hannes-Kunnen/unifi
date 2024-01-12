package unifi

import (
	"errors"
	"fmt"
	"net/http"
)

// FirewallRuleResponse is the representation of a response of a firewall rule request.
type FirewallRuleResponse struct {
	Meta Meta                       `json:"meta"`
	Data []FirewallRuleResponseData `json:"data"`
}

// FirewallRuleResponseData is the representation of the data inside the data array of the
// FirewallRuleResponse.
type FirewallRuleResponseData struct {
	FirewallRule
	DataValidationError
}

// FirewallRule is the representation of a firewall rule.
type FirewallRule struct {
	// The rule ID.
	Id string `json:"_id,omitempty"`
	// The ID of the site linked to this rule.
	SiteId string `json:"site_id,omitempty"`
	// The rule index, lower index is processed (matched) first.
	RuleIndex int `json:"rule_index,omitempty"`
	// Indicates whether the rule is active.
	Enabled bool `json:"enabled,omitempty"`
	// Determines in which direction and on which network the firewall rule is applied, options:
	//	- WAN_IN: IPv4 traffic coming from a WAN network, destined for other networks.
	//	- WAN_OUT: IPv4 traffic coming other networks, destined for a WAN network.
	//	- WAN_LOCAL: IPv4 traffic coming from a WAN network, destined for the UDM/USG.
	//	- LAN_IN: IPv4 traffic coming from a LAN network, destined for other networks.
	//	- LAN_OUT: IPv4 traffic coming other networks, destined for a LAN network.
	//	- LAN_LOCAL: IPv4 traffic coming from a LAN network, destined for the UDM/USG.
	//	- GUEST_IN: IPv4 traffic coming from a guest network, destined for other networks.
	//	- GUEST_OUT: IPv4 traffic coming other networks, destined for a guest network.
	//	- GUEST_LOCAL: IPv4 traffic coming from a guest network, destined for the UDM/USG.
	//	- WANv6_IN: IPv6 traffic coming from a WAN network, destined for other networks.
	//	- WANv6_OUT: IPv6 traffic coming other networks, destined for a WAN network.
	//	- WANv6_LOCAL: IPv6 traffic coming from a WAN network, destined for the UDM/USG.
	//	- LANv6_IN: IPv6 traffic coming from a LAN network, destined for other networks.
	//	- LANv6_OUT: IPv6 traffic coming other networks, destined for a LAN network.
	//	- LANv6_LOCAL: IPv6 traffic coming from a LAN network, destined for the UDM/USG.
	//	- GUESTv6_IN: IPv6 traffic coming from a guest network, destined for other networks.
	//	- GUESTv6_OUT: IPv6 traffic coming other networks, destined for a guest network.
	//	- GUESTv6_LOCAL: IPv6 traffic coming from a guest network, destined for the UDM/USG.
	Ruleset string `json:"ruleset,omitempty"`
	// The name of the rule.
	Name string `json:"name,omitempty"`
	// What action the rule should take, options:
	//	- accept: The traffic is allowed.
	//	- reject: The traffic is dropped and a response is sent back to the source.
	//	- drop: The traffic is dropped and no response is sent back.
	Action string `json:"action,omitempty"`
	// The protocol (IPv4) on which to apply this rule, options:
	//	- all: Any protocol will be matched.
	//	- tcp_udp: TCP and UPD traffic will be matched.
	//	- An IANA protocol number.
	//	- Any of the following protocols: tcp, udp, icmp, ah, ax.25, dccp, ddp, egp, eigrp, encap,
	//		esp, etherip, fc, ggp, gre, hip, hmp, idpr-cmtp, idrp, igmp, igp, ip, ipcomp, ipencap,
	//		ipip, ipv6, ipv6-frag, ipv6-icmp, ipv6-nonxt, ipv6-opts, ipv6-route, isis, iso-tp4,
	//		l2tp, manet, mobility-header, mpls-in-ip, ospf, pim, pup, rdp, rohc, rspf, rsvp, sctp,
	//		shim6, skip,st, udplite, vmtp, vrrp, wesp, xns-idp, xtp.
	Protocol string `json:"protocol,omitempty"`
	// The IPv4 ICMP control message type (name + code) when Protocol `icmp` is used.
	// The description of the following options might not be correct, it is based on matching the
	// name to the IANA registry data as there is no documentation provided:
	//	- any: Any ICMP type and code combination are allowed.
	//	- echo-reply: Type 0 - Echo Reply, Code 0 - No Code.
	//	- destination-unreachable: Type 3 - Destination Unreachable, Code unknown (all?).
	//	- network-unreachable: Type 3 - Destination Unreachable, Code 0 - Net Unreachable.
	//	- host-unreachable: Type 3 - Destination Unreachable, Code 1 - Host Unreachable.
	//	- protocol-unreachable: Type 3 - Destination Unreachable, Code 2 - Protocol Unreachable.
	//	- port-unreachable: Type 3 - Destination Unreachable, Code 3 - Port Unreachable.
	//	- fragmentation-needed: Type 3 - Destination Unreachable,
	//		Code 4 - Fragmentation Needed and Don't Fragment was Set.
	//	- source-route-failed: Type 3 - Destination Unreachable, Code 5 - Source Route Failed.
	//	- network-unknown: Type 3 - Destination Unreachable, Code 6 - Destination Network Unknown.
	//	- host-unknown: Type 3 - Destination Unreachable, Code 7 - Destination Host Unknown.
	//	- network-prohibited: Type 3 - Destination Unreachable,
	//		Code 9 - Communication with Destination Network is Administratively Prohibited.
	//	- host-prohibited: Type 3 - Destination Unreachable,
	//		Code 10 - Communication with Destination Host is Administratively Prohibited.
	//	- TOS-network-unreachable: Type 3 - Destination Unreachable,
	//		Code 11 - Destination Network Unreachable for Type of Service.
	//	- TOS-host-unreachable: Type 3 - Destination Unreachable,
	//		Code 12 - Destination Host Unreachable for Type of Service.
	//	- communication-prohibited: Type 3 - Destination Unreachable,
	//		Code 13 - Communication Administratively Prohibited.
	//	- host-precedence-violation: Type 3 - Destination Unreachable,
	//		Code 14 - Host Precedence Violation.
	//	- precedence-cutoff: Type 3 - Destination Unreachable,
	//		Code 15 - Precedence cutoff in effect.
	//		(Not available via UniFi UI)
	//	- source-quench: Type 4 - Source Quench (Deprecated), Code 0 - No Code.
	//		(Not available via UniFi UI)
	//	- redirect: Type 5 - Redirect, Code unknown (all?).
	//	- network-redirect: Type 5 - Redirect,
	//		Code 0 - Redirect Datagram for the Network (or subnet).
	//	- host-redirect: Type 5 - Redirect, Code 1 - Redirect Datagram for the Host.
	//	- TOS-network-redirect: Type 5 - Redirect,
	//		Code 2 - Redirect Datagram for the Type of Service and Network.
	//	- TOS-host-redirect: Type 5 - Redirect,
	//		Code 3 - Redirect Datagram for the Type of Service and Host.
	//	- echo-request: Type 8 - Echo, Code 0 - No Code.
	//	- router-advertisement: Type 9 - Router Advertisement, Code 0 - Normal router advertisement.
	//	- router-solicitation: Type 10 - Router Selection, Code 0 - No Code.
	//	- time-exceeded: Type 11 - Time Exceeded, Code unknown (all?).
	//	- ttl-zero-during-transit: Type 11 - Time Exceeded,
	//		Code 0 - Time to Live exceeded in Transit.
	//	- ttl-zero-during-reassembly: Type 11 - Time Exceeded,
	//		Code 1 - Fragment Reassembly Time Exceeded.
	//	- parameter-problem: Type 12 - Parameter Problem, Code 0 - Pointer indicates the error.
	//	- required-option-missing: Type 12 - Parameter Problem, Code 1 - Missing a Required Option.
	//	- ip-header-bad: Type 12 - Parameter Problem, Code 2 - Bad Length (unknown).
	//	- timestamp-request: Type 13 - Timestamp, Code 0 - No Code.
	//	- timestamp-reply: Type 14 - Timestamp Reply, Code 0 - No Code.
	//	- address-mask-request: Type 17 - Address Mask Request (Deprecated), Code 0 - No Code.
	//		(Not available via UniFi UI)
	//	- address-mask-reply: Type 18 - Address Mask Reply (Deprecated), Code 0 - No Code.
	//		(Not available via UniFi UI)
	ICMPTypename string `json:"icmp_typename,omitempty"`
	// The protocol (IPv6) on which to apply this rule, options:
	//	- all: Any protocol will be matched.
	//	- tcp_udp: TCP and UPD traffic will be matched.
	//	- An IANA protocol number.
	//	- Any of the following protocols: tcp, udp, icmpv6, ah, dccp, eigrp, esp, gre, ipcomp, ipv6,
	//		ipv6-frag, ipv6-icmp, ipv6-nonxt, ipv6-opts, ipv6-route, isis, l2tp, manet,
	//		mobility-header, mpls-in-ip, ospf, pim, rsvp, sctp, shim6, vrrp.
	ProtocolV6 string `json:"protocol_v6,omitempty"`
	// The IPv6 ICMP control message type (name + code) when ProtocolV6 `icmpv6` is used.
	// The description of the following options might not be correct, it is based on matching the
	// name to the IANA registry data as there is no documentation provided:
	//	- (empty): Any ICMP type and code combination are allowed.
	//	- destination-unreachable: Type 1 - Destination Unreachable, Code unknown (all?).
	//	- no-route: Type 1 - Destination Unreachable, Code 0 - no route to destination.
	//	- communication-prohibited: Type 1 - Destination Unreachable,
	//		Code 1 - communication with destination administratively prohibited.
	//	- beyond-scope: Type 1 - Destination Unreachable, Code 2 - beyond scope of source address.
	//		(Not available via UniFi UI)
	//	- address-unreachable: Type 1 - Destination Unreachable, Code 3 - address unreachable.
	//	- port-unreachable: Type 1 - Destination Unreachable, Code 4 - port unreachable.
	//	- failed-policy: Type 1 - Destination Unreachable,
	//		Code 5 - source address failed ingress/egress policy.
	//		(Not available via UniFi UI)
	//	- reject-route: Type 1 - Destination Unreachable, Code 6 - reject route to destination.
	//		(Not available via UniFi UI)
	//	- packet-too-big: Type 2 - Packet Too Big, Code 0.
	//	- time-exceeded: Type 3 - Time Exceeded, Code unknown (all?).
	//	- ttl-zero-during-transit: Type 3 - Time Exceeded, Code 0 - hop limit exceeded in transit.
	//	- ttl-zero-during-reassembly: Type 3 - Time Exceeded,
	//		Code 1 - fragment reassembly time exceeded.
	//	- parameter-problem: Type 4 - Parameter Problem, Code unknown (all?).
	//	- bad-header: Type 4 - Parameter Problem, Code unknown.
	//	- unknown-header-type: Type 4 - Parameter Problem,
	//		Code 1 - unrecognized Next Header type encountered.
	//	- unknown-option: Type 4 - Parameter Problem, Code 2 -unrecognized IPv6 option encountered.
	//	- echo-request: Type 128 - Echo Request, Code 0.
	//	- echo-reply: Type 129 - Echo Reply, Code 0.
	//	- router-solicitation: Type 133 - Router Solicitation, Code 0.
	//	- router-advertisement: Type 134 - Router Advertisement, Code 0.
	//	- neighbor-solicitation: Type 135 - Neighbor Solicitation, Code 0.
	//	- neighbor-advertisement: Type 136 - Neighbor Advertisement, Code 0.
	//	- redirect: Type 137 - Redirect Message, Code 0.
	ICMPv6Typename string `json:"icmpv6_typename,omitempty"`
	// Inverts the chosen Protocol or ProtocolV6, matches all protocols except the chosen one.
	// Can not be used when selecting the following protocols:
	//	- all (Protocol and ProtocolV6).
	//	- tcp_udp (Protocol).
	ProtocolMatchExcepted bool `json:"protocol_match_excepted,omitempty"`
	// IDs of the optional source address and/or port FirewallGroup(s).
	// Used for IPv6 rules or IPv4 rules with source type `Port/IP Group`.
	SrcFirewallGroupIds []string `json:"src_firewallgroup_ids,omitempty"`
	// ID of the source LAN network.
	// Used for IPv4 rules with source type `Network`.
	SrcNetworkConfId string `json:"src_networkconf_id,omitempty"`
	// Source network config type (IPv4), options:
	//	- ADDRv4: Network address (unclear!).
	//	- NETv4: Subnet (unclear!).
	SrcNetworkConfType string `json:"src_networkconf_type,omitempty"`
	// IPv4 address of the source machine.
	// Used for IPv4 rules with source type `IP Address`.
	SrcAddress string `json:"src_address,omitempty"`
	// Comma separated source port(s) and/or port range(s) e.g. "80,443,8000-9000".
	// Used for IPv4 rules with source type `IP Address`.
	// Can only be used when using Protocol `tcp`, `udp` or `tcp_udp`.
	SrcPort string `json:"src_port,omitempty"`
	// The MAC Address of the source machine
	SrcMacAddress string `json:"src_mac_address,omitempty"`
	// IDs of the optional destination address and/or port FirewallGroup(s).
	// Used for IPv6 rules or IPv4 rules with destination type `Port/IP Group`.
	DstFirewallGroupIds []string `json:"dst_firewallgroup_ids,omitempty"`
	// ID of the destination LAN network.
	// Used for IPv4 rules with destination type `Network`.
	DstNetworkConfId string `json:"dst_networkconf_id,omitempty"`
	// Destination network config type (IPv4), options:
	//	- ADDRv4: Network address (unclear!).
	//	- NETv4: Subnet (unclear!).
	DstNetworkConfType string `json:"dst_networkconf_type,omitempty"`
	// IPv4 address of the destination machine.
	// Used for IPv4 rules with destination type `IP Address`.
	DstAddress string `json:"dst_address,omitempty"`
	// Comma separated destination port(s) and/or port range(s) e.g. "80,443,8000-9000".
	// Used for IPv4 rules with destination type `IP Address`.
	// Can only be used when using Protocol `tcp`, `udp` or `tcp_udp`.
	DstPort string `json:"dst_port,omitempty"`
	// Indicates how advanced settings should be applied, options:
	//	- auto: Overrides advanced settings and sets them automatically.
	//	- manual: Advanced settings have to be set by the user.
	SettingPreference string `json:"setting_preference,omitempty"`
	// Match traffic state new.
	// If all state fields (StateNew, StateInvalid, StateEstablished, StateRelated) are set to
	// false, state is ignored during rule matching.
	// To use this setting set SettingPreference to `manual`
	StateNew bool `json:"state_new,omitempty"`
	// Match traffic state invalid.
	// If all state fields (StateNew, StateInvalid, StateEstablished, StateRelated) are set to
	// false, state is ignored during rule matching.
	// To use this setting set SettingPreference to `manual`
	StateInvalid bool `json:"state_invalid,omitempty"`
	// Match traffic state established.
	// If all state fields (StateNew, StateInvalid, StateEstablished, StateRelated) are set to
	// false, state is ignored during rule matching.
	// To use this setting set SettingPreference to `manual`
	StateEstablished bool `json:"state_established,omitempty"`
	// Match traffic state related.
	// If all state fields (StateNew, StateInvalid, StateEstablished, StateRelated) are set to
	// false, state is ignored during rule matching.
	// To use this setting set SettingPreference to `manual`
	StateRelated bool `json:"state_related,omitempty"`
	// IPsec rule matching settings, options:
	//	- (empty): Matches all traffic and not specifically IPsec or non-IPsec traffic (default).
	//	- match-ipsec: Match traffic that is encrypted by IPsec.
	//	- match-none: Match specifically on unencrypted traffic.
	// To use this setting set SettingPreference to `manual`
	Ipsec string `json:"ipsec,omitempty"`
	// Generates a syslog entry when this firewall rule is matched.
	// To use this setting set SettingPreference to `manual`
	Logging bool `json:"logging,omitempty"`
}

// CreateFirewallRule creates a new firewall rule linked to this Site using the given firewall rule
// data. It will return an error if the creation of the firewall rule failed.
func (site *Site) CreateFirewallRule(firewallRule FirewallRule) (FirewallRuleResponse, error) {
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

// GetAllFirewallRules returns all firewall rules linked to this Site.
// It will return an error if it fails to fetch the firewall rules.
func (site *Site) GetAllFirewallRules() (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", "")
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall rules failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// GetFirewallRule returns the firewall rule linked to the given ID and this Site.
// It will return an error if it fails to fetch the specific firewall rule, however if no rule
// with the given ID is present or the ID is invalid no error but a response with an empty data
// array will be returned.
func (site *Site) GetFirewallRule(id string) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", id)
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodGet, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("retreiving firewall rule failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// UpdateFirewallRule updates the firewall rule linked to the given ID and this Site using the
// given firewall rule data. It will return an error if the update of the firewall rule failed.
func (site *Site) UpdateFirewallRule(
	id string,
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
			fmt.Sprintf("firewall rule update failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}

// DeleteFirewallRule deletes the firewall rule linked to the given ID and this Site.
// It will return an error if the deletion of the firewall rule failed.
func (site *Site) DeleteFirewallRule(id string) (FirewallRuleResponse, error) {
	endpointUrl := site.createEndpointUrl("rest/firewallrule", id)
	responseData := FirewallRuleResponse{}

	res, err := site.controller.execute(http.MethodDelete, endpointUrl, nil, &responseData)
	if err != nil {
		return responseData, err
	}

	if res.StatusCode != 200 {
		return responseData, errors.New(
			fmt.Sprintf("deleting firewall rule failed with response code %d", res.StatusCode),
		)
	}

	return responseData, nil
}
