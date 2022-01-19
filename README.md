[comment]: # "Auto-generated SOAR connector documentation"
# Palo Alto Networks Firewall

Publisher: Splunk  
Connector Version: 2\.0\.19  
Product Vendor: Palo Alto Networks  
Product Name: Firewall  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with the Palo Alto Networks Firewall to support containment and investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2014-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This app creates, modifies, and deletes information that it creates on the PAN Firewall. As a
result, please do not edit addresses in PAN created by Phantom. Doing so may result in unexpected
behavior when performing actions on Phantom-created addresses.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Firewall asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** |  required  | string | Device IP/Hostname
**verify\_server\_cert** |  required  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[block url](#action-block-url) - Block an URL  
[unblock url](#action-unblock-url) - Unblock an URL  
[block application](#action-block-application) - Block an application  
[unblock application](#action-unblock-application) - Unblock an application  
[block ip](#action-block-ip) - Block an IP  
[unblock ip](#action-unblock-ip) - Unblock an IP  
[list applications](#action-list-applications) - List the applications that the device knows about and can block  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

This action logs into the device using a REST Api call to check the connection and credentials configured\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'block url'
Block an URL

Type: **contain**  
Read only: **False**

This action does the following to block an URL\:<ul><li>Create an URL Filtering profile object named <b>Phantom URL List</b>, if not found\.</li><li>Add the URL to block to this profile\.</li><li>Re\-Configure the policy <b>Phantom URL Security Policy</b> to use the created URL Filtering profile\.<br>The policy is created if not found\.</li><li>Move the policy above the <b>sec\_policy</b> if specified, else move it before the first detected <i>allow</i> policy\.</li><li>The action then proceeds to <b>commit</b> the changes\.</li></ul>NOTE\: Multiple <b>block url</b> actions will <i>not</i> result in multiple policies\.<br>The <b>Phantom URL Security Policy</b> policy is created with the following properties\:<br><ul><li>from\: any</li><li>to\: any</li><li>source\: any</li><li>destination\: any</li><li>source\-user\: any</li><li>category\: any</li><li>service\: application\-default</li><li>hip\-profiles\: any</li><li>description\: Created by Phantom, please don't edit</li><li>action\: allow</li><li>application\: any</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to block | string |  `url` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 
**sec\_policy** |  optional  | Insert above this policy | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.vsys | string | 
action\_result\.parameter\.sec\_policy | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock url'
Unblock an URL

Type: **correct**  
Read only: **False**

This action removes the URL from the <b>Phantom URL List</b> object, before proceeding to <b>commit</b> the configuration\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to block | string |  `url` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.vsys | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block application'
Block an application

Type: **contain**  
Read only: **False**

This action uses a multistep approach to block an application\:<ul><li>Create an application group named <b>Phantom App List</b> if not found\.</li>Add the application to block to this group</li><li>Configure the application group as the <i>application</i> to the policy named <b>Phantom App Security Policy</b>\.<br>The policy is created if not found on the device\.</li><li>The action then proceeds to <b>commit</b> the changes\.</li></ul>NOTE\: Multiple <b>block application</b> actions will <i>not</i> result in multiple policies or groups\. Instead the same App policy and group will be updated\.<br>The <b>Phantom App Security Policy</b> policy is created with the following properties\:<br><ul><li>from\: any</li><li>to\: any</li><li>source\: any</li><li>destination\: any</li><li>source\-user\: any</li><li>category\: any</li><li>service\: application\-default</li><li>hip\-profiles\: any</li><li>description\: Created by Phantom, please don't edit</li><li>action\: deny</li><li>application\: <b>Phantom App List</b></li></ul><br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**application** |  required  | Application to block | string |  `network application` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.vsys | string | 
action\_result\.parameter\.application | string |  `network application` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock application'
Unblock an application

Type: **correct**  
Read only: **False**

This action removes the app from the <b>Phantom App List</b> object, before proceeding to <b>commit</b> the configuration\.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**application** |  required  | Application to unblock | string |  `network application` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.vsys | string | 
action\_result\.parameter\.application | string |  `network application` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block ip'
Block an IP

Type: **contain**  
Read only: **False**

This action uses a multistep approach to block an IP\.  It behaves differently based upon whether <b>is\_source\_address</b> is true or not\.  By default, it is false\.  The approach is\:<ul><li>Create an address entry named '<b>\[ip\_address\] Added By Phantom</b>' with the specified IP address<li>The container id of the phantom action is added as a tag to the address entry when it's created<li>If <b>is\_source\_address</b> is false\:<br><ul><li>add this entry to an address group called <b>Phantom Network List</b></li><li>configure the address group as a <i>destination</i> to the policy named <b>Phantom IP Security Policy</b>\.<br>The <b>Phantom IP Security Policy</b> policy is created with the following properties\:<br><ul><li>from\: any<li>to\: any<li>source\: any<li>destination\: <b>Phantom Network List</b><li>source\-user\: any<li>category\: any<li>service\: application\-default<li>hip\-profiles\: any<li>description\: Created by Phantom, please don't edit<li>action\: deny<li>application\: any</ul></li></ul>If <b>is\_source\_address</b> is true\:<br><ul><li>add this entry to an address group called <b>Phantom Network List Source</b><li>configure the address group as a <i>source</i> to the policy named <b>Phantom src IP Security Policy\.</b>The <b>Phantom src IP Security Policy</b> policy is created with the following properties\:<br><ul><li>from\: any<li>to\: any<li>source\: <b>Phantom Network List Source</b><li>destination\: any<li>source\-user\: any<li>category\: any<li>service\: application\-default<li>hip\-profiles\: any<li>description\: Created by Phantom, please don't edit<li>action\: deny<li>application\: any</ul></li></ul><li>The policy is created if not found on the device\.</li><li>The action then proceeds to <b>commit</b> the changes\.</ul>NOTE\: Multiple <b>block ip</b> actions will <i>not</i> result in multiple policies or groups\.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to block | string |  `ip` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 
**is\_source\_address** |  optional  | Source address | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.vsys | string | 
action\_result\.parameter\.is\_source\_address | boolean | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock an IP

Type: **correct**  
Read only: **False**

</p>This action removes the IP from a specific Address Group depending upon whether <b>is\_source\_address</b> is true\.  By default, it is false\.</p>if <b>is\_source\_address</b> is false\:<ul><li>This action removes the IP from the <b>Phantom Network List</b> Address Group\.</li></ul>If <b>is\_source\_address</b> is true\:<ul><li>This action removes the IP from the <b>Phantom Network Source list</b> Address Group\.</li></ul><p>Afterwards, the action proceeds to <b>commit</b> the configuration\.<br>If the action parameter <b>vsys</b> is not specified then <b>'vsys1'</b> is used by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblock | string |  `ip` 
**vsys** |  optional  | Virtual system \(vsys\) to configure | string | 
**is\_source\_address** |  optional  | Source address | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.is\_source\_address | boolean | 
action\_result\.parameter\.vsys | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list applications'
List the applications that the device knows about and can block

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.\@name | string |  `network application` 
action\_result\.message | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.has\-known\-vulnerability | string | 
action\_result\.data\.\*\.used\-by\-malware | string | 
action\_result\.data\.\*\.\@ori\_country | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.consume\-big\-bandwidth | string | 
action\_result\.data\.\*\.able\-to\-transfer\-file | string | 
action\_result\.data\.\*\.technology | string | 
action\_result\.data\.\*\.pervasive\-use | string | 
action\_result\.data\.\*\.\@ori\_lauguage | string | 
action\_result\.data\.\*\.subcategory | string | 
action\_result\.data\.\*\.prone\-to\-misuse | string | 
action\_result\.data\.\*\.default\.port\.member | string | 
action\_result\.data\.\*\.evasive\-behavior | string | 
action\_result\.data\.\*\.references\.entry\.link | string | 
action\_result\.data\.\*\.references\.entry\.\@name | string | 
action\_result\.data\.\*\.tunnel\-other\-application | string | 
action\_result\.data\.\*\.\@id | string | 
action\_result\.data\.\*\.risk | string | 
action\_result\.data\.\*\.application\-container | string | 
action\_result\.data\.\*\.use\-applications\.member\.\#text | string | 
action\_result\.data\.\*\.use\-applications\.member\.\@minver | string | 
action\_result\.data\.\*\.use\-applications\.\@minver | string | 
action\_result\.data\.\*\.\@minver | string | 
action\_result\.data\.\*\.references\.entry\.\*\.link | string | 
action\_result\.data\.\*\.references\.entry\.\*\.\@name | string | 
action\_result\.data\.\*\.use\-applications\.member | string | 
action\_result\.data\.\*\.file\-type\-ident | string | 
action\_result\.data\.\*\.virus\-ident | string | 
action\_result\.data\.\*\.use\-applications\.member | string | 
action\_result\.data\.\*\.tunnel\-applications\.member | string | 
action\_result\.data\.\*\.data\-ident | string | 
action\_result\.data\.\*\.implicit\-use\-applications\.member | string | 
action\_result\.data\.\*\.default\.port\.member | string | 
action\_result\.data\.\*\.udp\-timeout | string | 
action\_result\.data\.\*\.default\.ident\-by\-ip\-protocol | string | 
action\_result\.data\.\*\.file\-forward | string | 
action\_result\.data\.\*\.use\-applications\.member\.\*\.\#text | string | 
action\_result\.data\.\*\.use\-applications\.member\.\*\.\@minver | string | 
action\_result\.data\.\*\.tunnel\-applications\.member\.\*\.\#text | string | 
action\_result\.data\.\*\.tunnel\-applications\.member\.\*\.\@minver | string | 
action\_result\.data\.\*\.tunnel\-applications\.\@minver | string | 
action\_result\.data\.\*\.ottawa\-name | string | 
action\_result\.data\.\*\.implicit\-use\-applications\.member | string | 
action\_result\.data\.\*\.decode | string | 
action\_result\.data\.\*\.breaks\-decryption | string | 
action\_result\.data\.\*\.tunnel\-applications\.member\.\#text | string | 
action\_result\.data\.\*\.tunnel\-applications\.member\.\@minver | string | 
action\_result\.data\.\*\.tunnel\-applications\.member | string | 
action\_result\.data\.\*\.related\-applications\.member | string | 
action\_result\.data\.\*\.child | string | 
action\_result\.data\.\*\.timeout | string | 
action\_result\.data\.\*\.analysis | string | 
action\_result\.data\.\*\.not\-support\-ssl | string | 
action\_result\.data\.\*\.enable\-url\-filter | string | 
action\_result\.data\.\*\.decode\.\#text | string | 
action\_result\.data\.\*\.decode\.\@minver | string | 
action\_result\.data\.\*\.correlate\.rules\.entry\.threshold | string | 
action\_result\.data\.\*\.correlate\.rules\.entry\.interval | string | 
action\_result\.data\.\*\.correlate\.rules\.entry\.protocol | string | 
action\_result\.data\.\*\.correlate\.rules\.entry\.track\-by\.member | string | 
action\_result\.data\.\*\.correlate\.rule\-match | string | 
action\_result\.data\.\*\.correlate\.interval | string | 
action\_result\.data\.\*\.correlate\.key\-by\.member | string | 
action\_result\.data\.\*\.tunnel\-other\-application\.\#text | string | 
action\_result\.data\.\*\.tunnel\-other\-application\.\@minver | string | 
action\_result\.data\.\*\.tcp\-timeout | string | 
action\_result\.data\.\*\.ident\-by\-dport | string | 
action\_result\.data\.\*\.file\-forward | string | 
action\_result\.data\.\*\.ident\-by\-sport | string | 
action\_result\.data\.\*\.preemptive | string | 
action\_result\.data\.\*\.use\-applications\.\*\.member | string | 
action\_result\.data\.\*\.netx\-vmotion | string | 
action\_result\.data\.\*\.ha\-safe | string | 
action\_result\.data\.\*\.timeout | string | 
action\_result\.data\.\*\.doc\-review | string | 
action\_result\.data\.\*\.default\.\*\.ident\-by\-ip\-protocol | string | 
action\_result\.data\.\*\.default\.\*\.port\.member | string | 
action\_result\.data\.\*\.discard\-timeout | string | 
action\_result\.data\.\*\.udp\-discard\-timeout | string | 
action\_result\.data\.\*\.default\.ident\-by\-icmp\-type | string | 
action\_result\.data\.\*\.deprecated | string | 
action\_result\.data\.\*\.alg\-disable\-capability | string | 
action\_result\.data\.\*\.risk | string | 
action\_result\.data\.\*\.tcp\-discard\-timeout | string | 
action\_result\.summary\.total\_applications | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 