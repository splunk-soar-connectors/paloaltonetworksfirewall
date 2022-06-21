# File: pan_consts.py
#
# Copyright (c) 2014-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
PAN_ERR_REPLY_FORMAT_KEY_MISSING = "'{key}' missing in the reply from the device"
PAN_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
PAN_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
PAN_SUCC_TEST_CONNECTIVITY_PASSED = "Test connectivity passed"
PAN_ERR_TEST_CONNECTIVITY_FAILED = "Test connectivity failed"
PAN_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
PAN_ERR_CREATE_UNKNOWN_TYPE_SEC_POL = "Asked to create unknown type of security policy"
PAN_ERR_INVALID_IP_FORMAT = "Invalid IP format"
PAN_ERR_DEVICE_CONNECTIVITY = "Error in connecting to device"
PAN_ERR_PARSE_POLICY_DATA = "Unable to parse security policy config"
PAN_ERR_NO_POLICY_ENTRIES_FOUND = "Could not find any security policies to update"
PAN_ERR_NO_ALLOW_POLICY_ENTRIES_FOUND = "Did not find any policies with an 'allow' action. Need at least one such policy"

PAN_PROG_USING_BASE_URL = "Using base URL '{base_url}'"
PAN_PROG_GOT_REPLY = "Got reply, parsing..."
PAN_PROG_PARSED_REPLY = "Done"
PAN_PROG_COMMIT_PROGRESS = "Commit completed {progress}%"

PAN_JSON_VSYS = "vsys"
PAN_JSON_URL = "url"
PAN_JSON_APPLICATION = "application"
PAN_JSON_IP = "ip"
PAN_JSON_TOTAL_APPLICATIONS = "total_applications"
PAN_JSON_SEC_POLICY = "sec_policy"
PAN_JSON_SOURCE_ADDRESS = "is_source_address"
PAN_DEFAULT_SOURCE_ADDRESS = False
PAN_DEFAULT_TIMEOUT = 30

# Name consts
SEC_POL_NAME = "Phantom {type} Security Policy"
SEC_POL_NAME_SRC = "Phantom src {type} Security Policy"
BLOCK_URL_CAT_NAME = "Phantom URL Category"
BLOCK_URL_PROF_NAME = "Phantom URL List"
BLOCK_IP_GROUP_NAME = "Phantom Network List"
BLOCK_IP_GROUP_NAME_SRC = "Phantom Network List Source"
BLOCK_APP_GROUP_NAME = "Phantom App List"
PHANTOM_ADDRESS_NAME = "Added By Phantom"

SEC_POL_URL_TYPE = "URL"
SEC_POL_APP_TYPE = "App"
SEC_POL_IP_TYPE = "IP"
MAX_NODE_NAME_LEN = 31

# Various xpaths and elem nodes

# This one is used to get all the policies
SEC_POL_RULES_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/rulebase/security/rules"

# This one is used while adding a security policy
SEC_POL_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/rulebase/security/rules/entry[@name='{sec_policy_name}']"

SEC_POL_DEF_ELEMS = "<from><member>any</member></from>"
SEC_POL_DEF_ELEMS += "<to><member>any</member></to>"
SEC_POL_DEF_ELEMS += "<source><member>any</member></source>"
SEC_POL_DEF_ELEMS += "<source-user><member>any</member></source-user>"
SEC_POL_DEF_ELEMS += "<category><member>any</member></category>"
SEC_POL_DEF_ELEMS += "<service><member>application-default</member></service>"
SEC_POL_DEF_ELEMS += "<description>Created by Phantom, please don't edit</description>"

SEC_POL_DEF_ELEMS_SRC = "<from><member>any</member></from>"
SEC_POL_DEF_ELEMS_SRC += "<to><member>any</member></to>"
SEC_POL_DEF_ELEMS_SRC += "<destination><member>any</member></destination>"
SEC_POL_DEF_ELEMS_SRC += "<source-user><member>any</member></source-user>"
SEC_POL_DEF_ELEMS_SRC += "<category><member>any</member></category>"
SEC_POL_DEF_ELEMS_SRC += "<service><member>application-default</member></service>"
SEC_POL_DEF_ELEMS_SRC += "<description>Created by Phantom, please don't edit</description>"

ACTION_NODE_DENY = "<action>deny</action>"
ACTION_NODE_ALLOW = "<action>allow</action>"
URL_PROF_SEC_POL_ELEM = "<profile-setting><profiles><url-filtering><member>{url_prof_name}</member></url-filtering></profiles></profile-setting>"
IP_GRP_SEC_POL_ELEM = "<destination><member>{ip_group_name}</member></destination>"
IP_GRP_SEC_POL_ELEM_SRC = "<source><member>{ip_group_name}</member></source>"
APP_GRP_SEC_POL_ELEM = "<application><member>{app_group_name}</member></application>"

URL_PROF_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/profiles/url-filtering/entry[@name='{url_profile_name}']"
URL_PROF_ELEM = "<description>Created by Phantom</description><block><member>{url_category_name}</member></block>"

URL_CAT_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/profiles/custom-url-category/entry[@name='{url_category_name}']"
URL_CAT_ELEM = "<description>Created by Phantom</description><list><member>{url}</member></list><type>URL List</type>"
DEL_URL_XPATH = "/list/member[text()='{url}']"

APP_GRP_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/application-group/entry[@name='{app_group_name}']"

APP_GRP_ELEM = "<members><member>{app_name}</member></members>"

DEL_APP_XPATH = "/members/member[text()='{app_name}']"

ADDR_GRP_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/address-group/entry[@name='{ip_group_name}']"
ADDR_GRP_ELEM = "<static><member>{addr_name}</member></static>"
DEL_ADDR_GRP_XPATH = "/static/member[text()='{addr_name}']"

IP_ADDR_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/address/entry[@name='{ip_addr_name}']"
IP_ADDR_ELEM = "<{type}>{ip}</{type}><tag><member>{tag}</member></tag>"

TAG_CONTAINER_COMMENT = "Phantom Container ID"
TAG_COLOR = "color7"
TAG_XPATH = "/config/devices/entry/vsys/entry[@name='{vsys}']/tag"
TAG_ELEM = "<entry name='{tag}'><color>{tag_color}</color><comments>{tag_comment}</comments></entry>"

APP_LIST_XPATH = "/config/predefined/application"
SHOW_SYSTEM_INFO = "<show><system><info></info></system></show>"

# The actions supported by this connector
ACTION_ID_BLOCK_URL = "block_url"
ACTION_ID_UNBLOCK_URL = "unblock_url"
ACTION_ID_BLOCK_APPLICATION = "block_application"
ACTION_ID_UNBLOCK_APPLICATION = "unblock_application"
ACTION_ID_BLOCK_IP = "block_ip"
ACTION_ID_UNBLOCK_IP = "unblock_ip"
ACTION_ID_LIST_APPS = "list_apps"
