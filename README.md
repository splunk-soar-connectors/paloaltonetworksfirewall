# Palo Alto Networks Firewall

Publisher: Splunk\
Connector Version: 2.1.1\
Product Vendor: Palo Alto Networks\
Product Name: Firewall\
Product Version Supported (regex): ".\*"\
Minimum Product Version: 5.3.3

This app integrates with the Palo Alto Networks Firewall to support containment and investigative actions

This app creates, modifies, and deletes information that it creates on the PAN Firewall. As a
result, please do not edit addresses in PAN created by Phantom. Doing so may result in unexpected
behavior when performing actions on SOAR-created addresses.

## Compatibility

From version 2.1.x onwards, the app only supports PAN Firewall version 9 and above.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Palo Alto Networks Firewall. Below are
the default ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http | tcp | 80 |
| https | tcp | 443 |

### Configuration Variables

The below configuration variables are required for this Connector to operate. These variables are specified when configuring a Firewall asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** | required | string | Device IP/Hostname
**verify_server_cert** | optional | boolean | Verify server certificate
**username** | required | string | Username
**password** | required | password | Password

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\
[block url](#action-block-url) - Block an URL\
[unblock url](#action-unblock-url) - Unblock an URL\
[block application](#action-block-application) - Block an application\
[unblock application](#action-unblock-application) - Unblock an application\
[block ip](#action-block-ip) - Block an IP\
[unblock ip](#action-unblock-ip) - Unblock an IP\
[list applications](#action-list-applications) - List the applications that the device knows about and can block. If the action parameter 'vsys' is not specified then 'vsys1' is used by default

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test**\
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'block url'

Block an URL

Type: **contain**\
Read only: **False**

This action does the following to block an URL:<ul><li>Create an URL category object named <b>Phantom URL Category</b>, if not found.</li><li>Add the URL to block to this category.</li><li>Create an URL Filtering profile object named <b>Phantom URL List</b>, if not found.</li><li>Add the Phantom URL Category to this profile.</li><li>Re-Configure the policy <b>Phantom URL Security Policy</b> to use the created URL Filtering profile.<br>The policy is created if not found.</li><li>Move the policy above the <b>sec_policy</b> if specified, else move it before the first detected <i>allow</i> policy.</li><li>The action then proceeds to <b>commit</b> the changes.</li></ul>NOTE: Multiple <b>block url</b> actions will <i>not</i> result in multiple categories/policies.<br>The <b>Phantom URL Security Policy</b> policy is created with the following properties:<br><ul><li>from: any</li><li>to: any</li><li>source: any</li><li>destination: any</li><li>source-user: any</li><li>category: any</li><li>service: application-default</li><li>hip-profiles: any / source-hip: any, destination-hip: any</li><li>description: Created by Phantom, please don't edit</li><li>action: allow</li><li>application: any</li></ul>.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to block | string | `url` `domain`
**vsys** | optional | Virtual system (vsys) to configure | string |
**sec_policy** | optional | Insert above this policy | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.sec_policy | string | | Test policy
action_result.parameter.url | string | `url` `domain` |\
action_result.parameter.vsys | string | | vsys1
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'unblock url'

Unblock an URL

Type: **correct**\
Read only: **False**

This action removes the URL from the <b>Phantom URL Category</b> object, before proceeding to <b>commit</b> the configuration.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to block | string | `url` `domain`
**vsys** | optional | Virtual system (vsys) to configure | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.url | string | `url` `domain` |\
action_result.parameter.vsys | string | | vsys1
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'block application'

Block an application

Type: **contain**\
Read only: **False**

This action uses a multistep approach to block an application:<ul><li>Create an application group named <b>Phantom App List</b> if not found.</li>Add the application to block to this group</li><li>Configure the application group as the <i>application</i> to the policy named <b>Phantom App Security Policy</b>.<br>The policy is created if not found on the device.</li><li>The action then proceeds to <b>commit</b> the changes.</li></ul>NOTE: Multiple <b>block application</b> actions will <i>not</i> result in multiple policies or groups. Instead the same App policy and group will be updated.<br>The <b>Phantom App Security Policy</b> policy is created with the following properties:<br><ul><li>from: any</li><li>to: any</li><li>source: any</li><li>destination: any</li><li>source-user: any</li><li>category: any</li><li>service: application-default</li><li>hip-profiles: any / source-hip: any, destination-hip: any</li><li>description: Created by Phantom, please don't edit</li><li>action: deny</li><li>application: <b>Phantom App List</b></li></ul><br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**application** | required | Application to block | string | `network application`
**vsys** | optional | Virtual system (vsys) to configure | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.application | string | `network application` |\
action_result.parameter.vsys | string | | vsys1
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'unblock application'

Unblock an application

Type: **correct**\
Read only: **False**

This action removes the app from the <b>Phantom App List</b> object, before proceeding to <b>commit</b> the configuration.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**application** | required | Application to unblock | string | `network application`
**vsys** | optional | Virtual system (vsys) to configure | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.application | string | `network application` |\
action_result.parameter.vsys | string | | vsys1
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'block ip'

Block an IP

Type: **contain**\
Read only: **False**

This action uses a multistep approach to block an IP. It behaves differently based upon whether <b>is_source_address</b> is true or not. By default, it is false. The approach is:<ul><li>Create an address entry with the specified IP address<li>The container id of the phantom action is added as a tag to the address entry when it's created<li>If <b>is_source_address</b> is false:<br><ul><li>add this entry to an address group called <b>Phantom Network List</b></li><li>configure the address group as a <i>destination</i> to the policy named <b>Phantom IP Security Policy</b>.<br>The <b>Phantom IP Security Policy</b> policy is created with the following properties:<br><ul><li>from: any<li>to: any<li>source: any<li>destination: <b>Phantom Network List</b><li>source-user: any<li>category: any<li>service: application-default<li>hip-profiles: any / source-hip: any, destination-hip: any<li>description: Created by Phantom, please don't edit<li>action: deny<li>application: any</ul></li></ul>If <b>is_source_address</b> is true:<br><ul><li>add this entry to an address group called <b>Phantom Network List Source</b><li>configure the address group as a <i>source</i> to the policy named <b>Phantom src IP Security Policy.</b>The <b>Phantom src IP Security Policy</b> policy is created with the following properties:<br><ul><li>from: any<li>to: any<li>source: <b>Phantom Network List Source</b><li>destination: any<li>source-user: any<li>category: any<li>service: application-default<li>hip-profiles: any / source-hip: any, destination-hip: any<li>description: Created by Phantom, please don't edit<li>action: deny<li>application: any</ul></li></ul><li>The policy is created if not found on the device.</li><li>The action then proceeds to <b>commit</b> the changes.</ul>NOTE: If the IP is of type wildcard mask, the address object is created without a tag and is directly added to the security policy. Multiple <b>block ip</b> actions will <i>not</i> result in multiple policies or groups.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to block | string | `ip` `ip network`
**vsys** | optional | Virtual system (vsys) to configure | string |
**is_source_address** | optional | Source address | boolean |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.ip | string | `ip` `ip network` |\
action_result.parameter.is_source_address | boolean | | True False
action_result.parameter.vsys | string | |\
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'unblock ip'

Unblock an IP

Type: **correct**\
Read only: **False**

</p>This action removes the IP from a specific Address Group depending upon whether <b>is_source_address</b> is true.  By default, it is false.</p>if <b>is_source_address</b> is false:<ul><li>This action removes the IP from the <b>Phantom Network List</b> Address Group.</li></ul>If <b>is_source_address</b> is true:<ul><li>This action removes the IP from the <b>Phantom Network Source list</b> Address Group.</li></ul><p>Afterwards, the action proceeds to <b>commit</b> the configuration.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default.<br/> NOTE: If the IP is of type wildcard mask, the action removes the IP from the security policy.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to unblock | string | `ip` `ip network`
**vsys** | optional | Virtual system (vsys) to configure | string |
**is_source_address** | optional | Source address | boolean |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.ip | string | `ip` `ip network` |\
action_result.parameter.is_source_address | boolean | | True False
action_result.parameter.vsys | string | | vsys1
action_result.data | string | |\
action_result.summary | string | |\
action_result.message | string | | REST API call succeeded. Code: '19'
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1

## action: 'list applications'

List the applications that the device knows about and can block. If the action parameter 'vsys' is not specified then 'vsys1' is used by default

Type: **investigate**\
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vsys** | optional | Virtual system (vsys) | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed
action_result.parameter.vsys | string | |\
action_result.data.\*.@id | string | | 1
action_result.data.\*.@minver | string | | 7.1.0
action_result.data.\*.@name | string | `network application` | Test app
action_result.data.\*.@ori_country | string | | USA
action_result.data.\*.@ori_language | string | | English
action_result.data.\*.@ori_lauguage | string | | English
action_result.data.\*.able-to-transfer-file | string | | yes
action_result.data.\*.alg-disable-capability | string | | sccp
action_result.data.\*.analysis | string | |\
action_result.data.\*.application-container | string | |\
action_result.data.\*.breaks-decryption | string | |\
action_result.data.\*.can-disable | string | | yes
action_result.data.\*.category | string | | general-internet
action_result.data.\*.child | string | | rpc
action_result.data.\*.consume-big-bandwidth | string | | yes
action_result.data.\*.correlate.interval | string | | 1000
action_result.data.\*.correlate.key-by.member | string | | source
action_result.data.\*.correlate.rule-match | string | | match-all
action_result.data.\*.correlate.rules.entry.interval | string | | 10
action_result.data.\*.correlate.rules.entry.protocol | string | | tcp
action_result.data.\*.correlate.rules.entry.threshold | string | | 3
action_result.data.\*.correlate.rules.entry.track-by.member | string | | source
action_result.data.\*.ctd-restart | string | | 1
action_result.data.\*.data-ident | string | |\
action_result.data.\*.data-ident.#text | string | | yes
action_result.data.\*.data-ident.@minver | string | | 8.1.0
action_result.data.\*.decode | string | |\
action_result.data.\*.decode.#text | string | | icmp
action_result.data.\*.decode.@minver | string | | 5.0.0
action_result.data.\*.default.\*.ident-by-ip-protocol | string | | 12
action_result.data.\*.default.\*.port.member | string | | icmp6/dynamic
action_result.data.\*.default.ident-by-icmp-type.@minver | string | | 7.0.0
action_result.data.\*.default.ident-by-icmp-type.type | string | | 8
action_result.data.\*.default.ident-by-icmp6-type.@minver | string | | 7.0.0
action_result.data.\*.default.ident-by-icmp6-type.type | string | | 128
action_result.data.\*.default.ident-by-ip-protocol | string | |\
action_result.data.\*.default.port.member | string | | udp/dynamic
action_result.data.\*.default.port.member | string | |\
action_result.data.\*.deprecated | string | | no
action_result.data.\*.discard-timeout | string | | 10
action_result.data.\*.enable-url-filter | string | | yes
action_result.data.\*.evasive-behavior | string | | no
action_result.data.\*.file-forward | string | |\
action_result.data.\*.file-forward | string | | yes
action_result.data.\*.file-forward.#text | string | | yes
action_result.data.\*.file-forward.@minver | string | | 6.1.0
action_result.data.\*.file-type-ident | string | |\
action_result.data.\*.ha-safe | string | | yes
action_result.data.\*.has-known-vulnerability | string | | yes
action_result.data.\*.icon.#text | string | |\
action_result.data.\*.icon.@minver | string | | 7.0.0
action_result.data.\*.ident-by-dport | string | | yes
action_result.data.\*.ident-by-sport | string | | yes
action_result.data.\*.implicit-use-applications.@minver | string | | 5.0.0
action_result.data.\*.implicit-use-applications.member | string | |\
action_result.data.\*.implicit-use-applications.member | string | |\
action_result.data.\*.implicit-use-applications.member.#text | string | | cotp
action_result.data.\*.implicit-use-applications.member.@minver | string | | 5.0.0
action_result.data.\*.is-saas | string | | yes
action_result.data.\*.netx-vmotion | string | | yes
action_result.data.\*.new-appid | string | | yes
action_result.data.\*.not-support-ssl | string | | no
action_result.data.\*.obsolete | string | | yes
action_result.data.\*.ottawa-name | string | |\
action_result.data.\*.parent-app | string | | iec-60870-5-104-base
action_result.data.\*.pervasive-use | string | | yes
action_result.data.\*.preemptive | string | | yes
action_result.data.\*.prone-to-misuse | string | | no
action_result.data.\*.references | string | |\
action_result.data.\*.references.entry.\*.@name | string | |\
action_result.data.\*.references.entry.\*.link | string | |\
action_result.data.\*.references.entry.@name | string | |\
action_result.data.\*.references.entry.link | string | |\
action_result.data.\*.related-applications.@minver | string | | 3.0.0
action_result.data.\*.related-applications.member | string | |\
action_result.data.\*.related-applications.member.#text | string | | posting
action_result.data.\*.related-applications.member.@minver | string | | 3.0.0
action_result.data.\*.risk | string | | 1
action_result.data.\*.risk | string | | 5
action_result.data.\*.saas.@minver | string | | 8.1.0
action_result.data.\*.saas.certifications.is-fedramp | string | | yes
action_result.data.\*.saas.certifications.is-finra | string | | yes
action_result.data.\*.saas.certifications.is-hipaa | string | | yes
action_result.data.\*.saas.certifications.is-pci | string | | yes
action_result.data.\*.saas.certifications.is-soc1 | string | | yes
action_result.data.\*.saas.certifications.is-soc2 | string | | yes
action_result.data.\*.saas.certifications.is-ssae16 | string | | yes
action_result.data.\*.saas.certifications.is-truste | string | | yes
action_result.data.\*.saas.is-data-breaches | string | | no
action_result.data.\*.saas.is-ip-based-restrictions | string | | no
action_result.data.\*.saas.is-poor-financial-viability | string | | no
action_result.data.\*.saas.is-poor-terms-of-service | string | | yes
action_result.data.\*.subcategory | string | | voip-video
action_result.data.\*.tag.@minver | string | | 9.1.0
action_result.data.\*.tag.member | string | | [Web App]
action_result.data.\*.tcp-discard-timeout | string | | 600
action_result.data.\*.tcp-timeout | string | | 3600
action_result.data.\*.technology | string | | peer-to-peer
action_result.data.\*.timeout | string | | 3600
action_result.data.\*.trusted-credential | string | | yes
action_result.data.\*.tunnel-applications.@minver | string | |\
action_result.data.\*.tunnel-applications.member | string | |\
action_result.data.\*.tunnel-applications.member.#text | string | |\
action_result.data.\*.tunnel-applications.member.\*.#text | string | |\
action_result.data.\*.tunnel-applications.member.\*.@minver | string | |\
action_result.data.\*.tunnel-applications.member.@minver | string | |\
action_result.data.\*.tunnel-other-application | string | | no
action_result.data.\*.tunnel-other-application.#text | string | | yes
action_result.data.\*.tunnel-other-application.@minver | string | | 3.1.0
action_result.data.\*.udp-discard-timeout | string | | 1200
action_result.data.\*.udp-timeout | string | |\
action_result.data.\*.use-applications.\*.member | string | | web-browsing
action_result.data.\*.use-applications.@minver | string | | 3.1.0
action_result.data.\*.use-applications.member | string | |\
action_result.data.\*.use-applications.member.#text | string | |\
action_result.data.\*.use-applications.member.\*.#text | string | |\
action_result.data.\*.use-applications.member.\*.@minver | string | |\
action_result.data.\*.use-applications.member.@minver | string | | 3.1.0
action_result.data.\*.used-by-malware | string | | yes
action_result.data.\*.video-type | string | | yes
action_result.data.\*.virus-ident | string | |\
action_result.summary.total_applications | numeric | |\
action_result.message | string | |\
summary.total_objects | numeric | | 1
summary.total_objects_successful | numeric | | 1
