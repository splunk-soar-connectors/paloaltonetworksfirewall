[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2014-2023 Splunk Inc."
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
behavior when performing actions on SOAR-created addresses.

## Compatibility

From version 2.1.x onwards, the app only supports PAN Firewall version 9 and above.

## Port Details

The app uses HTTP/ HTTPS protocol for communicating with the Palo Alto Networks Firewall. Below are
the default ports used by the Splunk SOAR Connector.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |
