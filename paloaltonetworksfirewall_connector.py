# File: paloaltonetworksfirewall_connector.py
#
# Copyright (c) 2014-2023 Splunk Inc.
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
#
#
import hashlib
import ipaddress
import json
import re
import time

import phantom.app as phantom
import requests
import xmltodict
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from paloaltonetworksfirewall_consts import *


class PanConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(PanConnector, self).__init__()

        self._base_url = None
        self._key = None
        self._sec_policy = None
        self._ip_type = None

    def _is_ip(self, input_ip_address):

        try:
            ipaddress.ip_address(input_ip_address)
        except Exception:
            return False

        return True

    def initialize(self):

        config = self.get_config()

        self._username = config[phantom.APP_JSON_USERNAME]
        self._password = config[phantom.APP_JSON_PASSWORD]
        self._device = config[phantom.APP_JSON_DEVICE]
        self._verify = config.get(phantom.APP_JSON_VERIFY, True)

        # Base URL
        self._base_url = 'https://{}/api/'.format(self._device)

        return phantom.APP_SUCCESS

    def _parse_response_msg(self, response, action_result):

        msg = response.get('msg')

        if msg is None:
            return

        # parse it as a dictionary
        if isinstance(msg, dict):
            line = msg.get('line')
            if line is None:
                return
            if isinstance(line, list):
                action_result.append_to_message("Message: '{}'".format(', '.join(line)))
            else:
                action_result.append_to_message("Message: '{}'".format(line))
            return

        # Covert msg from bytes to str type
        if type(msg) == bytes:
            msg = msg.decode('utf-8')
        # parse it as a string
        if type(msg) == str:
            action_result.append_to_message("Message: '{}'".format(msg))

        return

    def _parse_response(self, response_dict, action_result):

        # multiple keys could be present even if the response is a failure
        self.debug_print('response_dict', response_dict)

        response = response_dict.get('response')

        if response is None:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response'))

        status = response.get('@status')

        if status is None:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/status'))

        if status != 'success':
            action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_NOT_SUCC.format(status=status))
        else:
            action_result.set_status(phantom.APP_SUCCESS, PAN_SUCC_REST_CALL_SUCCEEDED)

        code = response.get('@code')
        if code is not None:
            action_result.append_to_message("Code: '{}'".format(code))

        self._parse_response_msg(response, action_result)

        result = response.get('result')

        if result is not None:
            action_result.add_data(result)

        return action_result.get_status()

    def _get_key(self, action_result):

        data = {'type': 'keygen', 'user': self._username, 'password': self._password}

        try:
            response = requests.post(self._base_url, data=data, verify=self._verify, timeout=PAN_DEFAULT_TIMEOUT)
        except Exception as e:
            self.error_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return action_result.set_status(phantom.APP_ERROR, "{}: {}".format(PAN_ERR_DEVICE_CONNECTIVITY, str(e)))

        try:
            xml = response.text
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            self.error_print(PAN_ERR_UNABLE_TO_PARSE_REPLY, e)
            return action_result.set_status(phantom.APP_ERROR, "{}: {}".format(PAN_ERR_UNABLE_TO_PARSE_REPLY, str(e)))

        response = response_dict.get('response')

        if response is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response')
            return action_result.set_status(phantom.APP_ERROR, message)

        status = response.get('@status')

        if status is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/status')
            return action_result.set_status(phantom.APP_ERROR, message)

        if status != 'success':
            message = PAN_ERR_REPLY_NOT_SUCC.format(status=status)
            json_resp = json.dumps(response).replace('{', ':').replace('}', '')
            message += ". Response from server: {0}".format(json_resp)
            return action_result.set_status(phantom.APP_ERROR, message)

        result = response.get('result')

        if result is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result')
            return action_result.set_status(phantom.APP_ERROR, message)

        key = result.get('key')

        if key is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result/key')
            return action_result.set_status(phantom.APP_ERROR, message)

        self._key = key

        ver_ar = ActionResult()

        ret_val = self._validate_version(ver_ar)

        if phantom.is_fail(ret_val):
            return action_result.set_status(ret_val, ver_ar.get_message())

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(PAN_PROG_USING_BASE_URL.format(base_url=self._base_url))

        status = self._get_key(action_result)

        if phantom.is_fail(status):
            self.save_progress(PAN_ERR_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()

        self.save_progress(PAN_SUCC_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _make_rest_call(self, data, action_result):

        self.debug_print("Making rest call")

        try:
            response = requests.post(self._base_url, data=data, verify=self._verify, timeout=PAN_DEFAULT_TIMEOUT)
        except Exception as e:
            self.error_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return action_result.set_status(phantom.APP_ERROR, "{}: {}".format(PAN_ERR_DEVICE_CONNECTIVITY, str(e)))

        try:
            xml = response.text
            if hasattr(action_result, 'add_debug_data'):
                action_result.add_debug_data({'r_text': xml})

            response_dict = xmltodict.parse(xml)
        except Exception as e:
            self.error_print(PAN_ERR_UNABLE_TO_PARSE_REPLY, e)
            return action_result.set_status(phantom.APP_ERROR, "{}: {}".format(PAN_ERR_UNABLE_TO_PARSE_REPLY, str(e)))

        self._parse_response(response_dict, action_result)

        return action_result.get_status()

    def _get_first_allow_policy(self, action_result):

        ret_name = None
        result_data = action_result.get_data()

        if len(result_data) == 0:
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_PARSE_POLICY_DATA), ret_name)

        result_data = result_data[0]

        rules = result_data.get('rules', {})

        entries = rules.get('entry')

        if entries is None:
            # Just means no rules have been configured
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_POLICY_ENTRIES_FOUND), ret_name)

        # Convert entries into array, if it's a dict (this will happen if there is only one rule)
        if isinstance(entries, dict):
            entry_list = []
            entry_list.append(entries)
            entries = entry_list

        for entry in entries:
            action = entry.get('action')
            if action is None:
                continue
            if isinstance(action, dict):
                action = action.get('#text')

            if action == 'allow':
                ret_name = entry.get('@name')
                break

        if ret_name is None:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_ALLOW_POLICY_ENTRIES_FOUND), ret_name

        return action_result.set_status(phantom.APP_SUCCESS), ret_name

    def _add_url_security_policy(self, vsys, action_result, type):

        element = SEC_POL_DEF_ELEMS

        sec_policy_name = SEC_POL_NAME.format(type=type)
        allow_rule_name = self._sec_policy

        self.debug_print("Creating security policy: {}".format(sec_policy_name))

        # The URL policy is actually an 'allow' policy, which uses a URL Profile with block lists.
        # That's the way to block urls in PAN.
        # So the policy needs to be placed just before the topmost 'allow' policy for things to work properly.
        # So get the list of all the security policies, we need to parse through them to get the first 'allow'
        # However if the user has already supplied a policy name, then use that.

        if allow_rule_name is None:
            data = {'type': 'config',
                    'action': 'get',
                    'key': self._key,
                    'xpath': SEC_POL_RULES_XPATH.format(vsys=vsys)}

            policy_list_act_res = ActionResult()

            status = self._make_rest_call(data, policy_list_act_res)

            if phantom.is_fail(status):
                return action_result.set_status(policy_list_act_res.get_status(), policy_list_act_res.get_message())

            status, allow_rule_name = self._get_first_allow_policy(policy_list_act_res)

            if phantom.is_fail(status):
                return action_result.set_status(status, policy_list_act_res.get_message())

        element += ACTION_NODE_ALLOW
        element += URL_PROF_SEC_POL_ELEM.format(url_prof_name=BLOCK_URL_PROF_NAME)
        element += APP_GRP_SEC_POL_ELEM.format(app_group_name="any")
        element += IP_GRP_SEC_POL_ELEM.format(ip_group_name="any")

        if self._major_version > 9:
            element += "<source-hip><member>any</member></source-hip><destination-hip><member>any</member></destination-hip>"
        else:
            element += "<hip-profiles><member>any</member></hip-profiles>"

        xpath = SEC_POL_XPATH.format(vsys=vsys, sec_policy_name=sec_policy_name)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if allow_rule_name == sec_policy_name:
            # We are the first allow rule, so no need to move
            return action_result.get_status()

        # move it to the top of the first policy with an allow action
        data = {'type': 'config',
                'action': 'move',
                'key': self._key,
                'xpath': xpath,
                'where': 'before',
                'dst': allow_rule_name}

        move_action_result = ActionResult()

        status = self._make_rest_call(data, move_action_result)

        if phantom.is_fail(status):
            # check if we also treat this error as an error
            msg = move_action_result.get_message()
            if msg.find('already at the top') == -1:
                # looks like an error that we should report
                action_result.set_status(move_action_result.get_status(), move_action_result.get_message())
                return action_result.get_status()

        return action_result.get_status()

    def _add_security_policy(self, vsys, action_result, type, name=None, use_source=False, block_ip_grp=None):

        if use_source:
            sec_policy_name = SEC_POL_NAME_SRC.format(type=type)
            element = SEC_POL_DEF_ELEMS_SRC
        else:
            sec_policy_name = SEC_POL_NAME.format(type=type)
            element = SEC_POL_DEF_ELEMS

        if self._major_version > 9:
            element += "<source-hip><member>any</member></source-hip><destination-hip><member>any</member></destination-hip>"
        else:
            element += "<hip-profiles><member>any</member></hip-profiles>"

        self.debug_print("Creating Security Policy: {}".format(sec_policy_name))

        if type == SEC_POL_URL_TYPE:
            # URL needs to be handled differently
            return self._add_url_security_policy(vsys, action_result, type)
        elif type == SEC_POL_IP_TYPE:
            element += ACTION_NODE_DENY
            element += APP_GRP_SEC_POL_ELEM.format(app_group_name="any")
            if use_source:
                element += IP_GRP_SEC_POL_ELEM_SRC.format(ip_group_name=block_ip_grp)
            else:
                element += IP_GRP_SEC_POL_ELEM.format(ip_group_name=block_ip_grp)
        elif type == SEC_POL_APP_TYPE:
            element += ACTION_NODE_DENY
            element += APP_GRP_SEC_POL_ELEM.format(app_group_name=name)
            element += IP_GRP_SEC_POL_ELEM.format(ip_group_name="any")

        xpath = SEC_POL_XPATH.format(vsys=vsys, sec_policy_name=sec_policy_name)
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # move it to the top
        data = {'type': 'config',
                'action': 'move',
                'key': self._key,
                'xpath': xpath,
                'where': 'top'}

        move_action_result = ActionResult()

        status = self._make_rest_call(data, move_action_result)

        if phantom.is_fail(status):
            # check if we also treat this error as an error
            msg = move_action_result.get_message()
            if msg.find('already at the top') == -1:
                # looks like an error that we should report
                action_result.set_status(move_action_result.get_status(), move_action_result.get_message())
                return action_result.get_status()

        return action_result.get_status()

    def _commit_config(self, action_result):

        self.debug_print("Committing the config")

        data = {'type': 'commit',
                'cmd': '<commit></commit>',
                'key': self._key}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Get the job id of the commit call from the result_data, also pop it since we don't need it
        # to be in the action result
        result_data = action_result.get_data()

        if len(result_data) == 0:
            return action_result.get_status()

        result_data = result_data.pop(0)
        job_id = result_data.get('job')

        self.debug_print("Commit job id: {}".format(job_id))

        while True:
            data = {'type': 'op',
                    'key': self._key,
                    'cmd': '<show><jobs><id>{job}</id></jobs></show>'.format(job=job_id)}

            status_action_result = ActionResult()

            status = self._make_rest_call(data, status_action_result)

            if phantom.is_fail(status):
                action_result.set_status(phantom.APP_SUCCESS, status_action_result.get_message())
                return action_result.get_status()

            self.debug_print("status", status_action_result)

            # get the result_data and the job status
            result_data = status_action_result.get_data()
            job = result_data[0].get('job', {})
            if job.get('status') == 'FIN':
                break

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job.get('progress'))

            time.sleep(2)

        return action_result.get_status()

    def _unblock_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        self.debug_print("Removing the blocked URL")

        block_url = param[PAN_JSON_URL]

        xpath = "{0}{1}".format(URL_CAT_XPATH.format(vsys=vsys, url_category_name=BLOCK_URL_CAT_NAME),
                DEL_URL_XPATH.format(url=block_url))

        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _block_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')
        self._sec_policy = param.get(PAN_JSON_SEC_POLICY)

        self.debug_print("Creating custom URL category")
        block_url = param[PAN_JSON_URL]
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': URL_CAT_XPATH.format(vsys=vsys, url_category_name=BLOCK_URL_CAT_NAME),
                'element': URL_CAT_ELEM.format(url=block_url)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        self.debug_print("Adding URL category to URL filtering profile")
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': URL_PROF_XPATH.format(vsys=vsys, url_profile_name=BLOCK_URL_PROF_NAME),
                'element': URL_PROF_ELEM.format(url_category_name=BLOCK_URL_CAT_NAME)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Create the policy
        status = self._add_security_policy(vsys, action_result, SEC_POL_URL_TYPE)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _unblock_application(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        block_app = param[PAN_JSON_APPLICATION]

        xpath = "{0}{1}".format(APP_GRP_XPATH.format(vsys=vsys, app_group_name=BLOCK_APP_GROUP_NAME),
                DEL_APP_XPATH.format(app_name=block_app))

        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _block_application(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        self.debug_print("Creating the Application Group")

        block_app = param[PAN_JSON_APPLICATION]

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': APP_GRP_XPATH.format(vsys=vsys, app_group_name=BLOCK_APP_GROUP_NAME),
                'element': APP_GRP_ELEM.format(app_name=block_app)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Create the policy
        status = self._add_security_policy(vsys, action_result, SEC_POL_APP_TYPE, BLOCK_APP_GROUP_NAME)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _get_addr_name(self, ip):

        # Remove the slash in the ip if present, PAN does not like slash in the names
        rem_slash = lambda x: re.sub(r'(.*)/(.*)', r'\1 mask \2', x)
        if self._ip_type == "ip-wildcard":
            rem_slash = lambda x: re.sub(r'(.*)/(.*)', r'\1 wildcard mask \2', x)

        new_ip = ip.replace("-", " - ").replace(":", "-")
        if not new_ip[0].isalnum():
            name = "{0} {1}".format(PHANTOM_ADDRESS_NAME, rem_slash(new_ip))
        else:
            name = "{0} {1}".format(rem_slash(new_ip), PHANTOM_ADDRESS_NAME)

        # Object name can't exceed 63 characters
        if len(name) > 63:
            name = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:-1]

        return name

    def find_ip_type(self, ip):
        if ip.find('/') != -1:
            try:
                int(ip.split('/')[1])
                self._ip_type = 'ip-netmask'
            except Exception:
                self._ip_type = 'ip-wildcard'
        elif ip.find('-') != -1:
            self._ip_type = 'ip-range'
        elif self._is_ip(ip):
            self._ip_type = 'ip-netmask'
        elif phantom.is_hostname(ip):
            self._ip_type = 'fqdn'

    def _add_address(self, vsys, block_ip, action_result):

        name = None

        tag = self.get_container_id()

        # Add the tag to the system
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': TAG_XPATH.format(vsys=vsys),
                'element': TAG_ELEM.format(tag=tag, tag_comment=TAG_CONTAINER_COMMENT, tag_color=TAG_COLOR)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status(), name

        # Try to figure out the type of ip
        self.find_ip_type(block_ip)
        if not self._ip_type:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT), name

        name = self._get_addr_name(block_ip)

        address_xpath = IP_ADDR_XPATH.format(vsys=vsys, ip_addr_name=name)

        if self._ip_type == "ip-wildcard":
            # Wildcards do not support tags
            element = IP_ADDR_ELEM_WITHOUT_TAG.format(type=self._ip_type, ip=block_ip)
        else:
           element = IP_ADDR_ELEM.format(type=self._ip_type, ip=block_ip, tag=tag)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': address_xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status(), name

        return phantom.APP_SUCCESS, name

    def _unblock_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        # Create the ip addr name
        unblock_ip = param[PAN_JSON_IP]
        # Sanitize the ip value
        unblock_ip = unblock_ip.replace(" ", "").strip("/").strip("-")

        if not unblock_ip:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT)

        # Try to figure out the type of ip
        self.find_ip_type(unblock_ip)
        if not self._ip_type:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT)

        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC
            sec_policy_name = SEC_POL_NAME_SRC.format(type='IP')
            entry_type = "source"
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME
            sec_policy_name = SEC_POL_NAME.format(type='IP')
            entry_type = "destination"

        addr_name = self._get_addr_name(unblock_ip)

        if self._ip_type == "ip-wildcard":
            # Remove the entry of the IP from the rule
            xpath = "{}/{entry_type}/member[text()='{addr_name}']".format(SEC_POL_XPATH.format(vsys=vsys, sec_policy_name=sec_policy_name),
                entry_type=entry_type, addr_name=addr_name)
        else:
            # Remove the entry of the IP from the address group
            xpath = "{0}{1}".format(ADDR_GRP_XPATH.format(vsys=vsys, ip_group_name=block_ip_grp),
                DEL_ADDR_GRP_XPATH.format(addr_name=addr_name))

        # Remove the address from the phantom address group
        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _block_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        # First create the ip
        self.debug_print("Adding the IP Group")

        block_ip = param[PAN_JSON_IP]
        # Sanitize the ip value
        block_ip = block_ip.replace(" ", "").strip("/").strip("-")
        if not block_ip:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT)

        # check and pass to create policy
        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME

        status, addr_name = self._add_address(vsys, block_ip, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        self.debug_print(f"IP type: {self._ip_type}")
        if self._ip_type == 'ip-wildcard':
            # Wildcard IP has to be added to the security policy rule
            block_ip_grp = addr_name
        else:
            # Add the address to the phantom address group
            data = {'type': 'config',
                    'action': 'set',
                    'key': self._key,
                    'xpath': ADDR_GRP_XPATH.format(vsys=vsys, ip_group_name=block_ip_grp),
                    'element': ADDR_GRP_ELEM.format(addr_name=addr_name)}

            status = self._make_rest_call(data, action_result)

            if phantom.is_fail(status):
                return action_result.get_status()

        # Create the policy
        status = self._add_security_policy(vsys, action_result, SEC_POL_IP_TYPE, use_source=use_source, block_ip_grp=block_ip_grp)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit the config
        status = self._commit_config(action_result)

        return action_result.get_status()

    def _list_apps(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        status = self._get_key(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Add the address to the phantom address group
        data = {'type': 'config',
                'action': 'get',
                'key': self._key,
                'xpath': APP_LIST_XPATH}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        results = list()
        try:
            # Move things around, so that result data is an array of applications
            result_data = action_result.get_data().pop(0)
            applications = result_data.get('application')
            if applications:
                results.extend(result_data['application']['entry'])
        except Exception as e:
            self.error_print("Handled exception while parsing predefined applications response", e)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_APP_RESPONSE)

        vsys = param.get(PAN_JSON_VSYS, 'vsys1')
        # Fetch the list of vsys visible custom applications
        data['xpath'] = CUSTOM_APP_LIST_XPATH.format(vsys=vsys)

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Code: '7'" in action_result.get_message():
            return action_result.set_status(phantom.APP_ERROR, PAN_REST_CALL_FAILED.format(code="7", message="Object not present"))

        try:
            result_data = action_result.get_data().pop(0)
            applications = result_data.get('application')
            if applications:
                results.extend(result_data['application']['entry'])
        except Exception as e:
            self.error_print("Handled exception while parsing custom applications response", e)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_APP_RESPONSE)

        action_result.update_data(results)

        action_result.update_summary({PAN_JSON_TOTAL_APPLICATIONS: len(results)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_version(self, action_result):

        # make a rest call to get the info
        data = {'type': 'op',
                'key': self._key,
                'cmd': SHOW_SYSTEM_INFO}

        ver_ar = ActionResult()

        status = self._make_rest_call(data, ver_ar)

        if phantom.is_fail(status):
            action_result.set_status(ver_ar.get_status(), ver_ar.get_message())
            return action_result.get_status()

        # get the version of the device
        try:
            result_data = ver_ar.get_data()
            result_data = result_data.pop(0)
            device_version = result_data['system']['sw-version']
        except Exception as e:
            self.error_print("Handled exception while parsing sw-version", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse system info response")

        if not device_version:
            return action_result.set_status(phantom.APP_ERROR, "Unable to get version from the device")

        self.save_progress("Got device version: {0}".format(device_version))

        # get the configured version regex
        version_regex = self.get_product_version_regex()
        if not version_regex:
            # assume that it matches
            return phantom.APP_SUCCESS

        match = re.match(version_regex, device_version)

        if not match:
            message = "Version validation failed for app supported version '{0}'".format(version_regex)
            return action_result.set_status(phantom.APP_ERROR, message)

        self._major_version = int(device_version.split('.')[0])

        return phantom.APP_SUCCESS

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == ACTION_ID_BLOCK_URL:
            result = self._block_url(param)
        elif action == ACTION_ID_UNBLOCK_URL:
            result = self._unblock_url(param)
        elif action == ACTION_ID_BLOCK_APPLICATION:
            result = self._block_application(param)
        elif action == ACTION_ID_UNBLOCK_APPLICATION:
            result = self._unblock_application(param)
        elif action == ACTION_ID_BLOCK_IP:
            result = self._block_ip(param)
        elif action == ACTION_ID_UNBLOCK_IP:
            result = self._unblock_ip(param)
        elif action == ACTION_ID_LIST_APPS:
            result = self._list_apps(param)

        return result


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
            r = requests.get(login_url, verify=verify, timeout=PAN_DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=PAN_DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PanConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
