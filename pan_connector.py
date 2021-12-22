# File: pan_connector.py
#
# Copyright (c) 2014-2021 Splunk Inc.
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
import json
import re
import time

import phantom.app as phantom
import requests
import xmltodict
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from pan_consts import *


class PanConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_BLOCK_URL = "block_url"
    ACTION_ID_UNBLOCK_URL = "unblock_url"
    ACTION_ID_BLOCK_APPLICATION = "block_application"
    ACTION_ID_UNBLOCK_APPLICATION = "unblock_application"
    ACTION_ID_BLOCK_IP = "block_ip"
    ACTION_ID_UNBLOCK_IP = "unblock_ip"
    ACTION_ID_LIST_APPS = "list_apps"

    def __init__(self):

        # Call the BaseConnectors init first
        super(PanConnector, self).__init__()

        self._base_url = None
        self._key = None
        self._param = None
        self._device_version = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        self._base_url = 'https://' + config[phantom.APP_JSON_DEVICE] + '/api/'

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
                action_result.append_to_message("message: '{}'".format(', '.join(line)))
            else:
                action_result.append_to_message("message: '{}'".format(line))
            return

        # Covert msg from bytes to str type
        if type(msg) == bytes:
            msg = msg.decode('utf-8')
        # parse it as a string
        if type(msg) == str:
            action_result.append_to_message("message: '{}'".format(msg))

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
            action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_NOT_SUCCESS.format(status=status))
        else:
            action_result.set_status(phantom.APP_SUCCESS, PAN_SUCC_REST_CALL_SUCCEEDED)

        code = response.get('@code')
        if code is not None:
            action_result.append_to_message("code: '{}'".format(code))

        self._parse_response_msg(response, action_result)

        result = response.get('result')

        if result is not None:
            action_result.add_data(result)

        return action_result.get_status()

    def _get_key(self):

        if self._key is not None:
            # key already created for this call
            return phantom.APP_SUCCESS

        config = self.get_config()

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, config[phantom.APP_JSON_DEVICE])
        username = config[phantom.APP_JSON_USERNAME]
        password = config[phantom.APP_JSON_PASSWORD]

        data = {'type': 'keygen', 'user': username, 'password': password}

        try:
            response = requests.post(self._base_url, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return self.set_status(phantom.APP_ERROR, PAN_ERR_DEVICE_CONNECTIVITY, e)

        xml = response.text

        # self.save_progress(PAN_PROG_GOT_REPLY)
        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, PAN_ERR_UNABLE_TO_PARSE_REPLY, e)

        response = response_dict.get('response')

        if response is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response')
            return self.set_status(phantom.APP_ERROR, message)

        status = response.get('@status')

        if status is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/status')
            return self.set_status(phantom.APP_ERROR, message)

        if status != 'success':
            message = PAN_ERR_REPLY_NOT_SUCCESS.format(status=status)
            json_resp = json.dumps(response).replace('{', ':')
            json_resp = json_resp.replace('}', '')
            message += ". Response from server: {0}".format(json_resp)
            return self.set_status(phantom.APP_ERROR, message)

        result = response.get('result')

        if result is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result')
            return self.set_status(phantom.APP_ERROR, message)

        key = result.get('key')

        if key is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result/key')
            return self.set_status(phantom.APP_ERROR, message)

        self._key = key

        ver_ar = ActionResult()

        ret_val = self._validate_version(ver_ar)

        if phantom.is_fail(ret_val):
            self.set_status(ret_val, ver_ar.get_message())
            self.append_to_message(PAN_ERR_TEST_CONNECTIVITY_FAILED)
            return self.get_status()

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(PAN_PROG_USING_BASE_URL, base_url=self._base_url)

        status = self._get_key()

        if phantom.is_fail(status):
            self.append_to_message(PAN_ERR_TEST_CONNECTIVITY_FAILED)
            return self.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, PAN_SUCC_TEST_CONNECTIVITY_PASSED)
        return self.get_status()

    def _make_rest_call(self, data, action_result):

        self.debug_print("Making rest call")

        self.debug_print("_make_rest_call::data", data)

        config = self.get_config()

        try:
            response = requests.post(self._base_url, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_DEVICE_CONNECTIVITY, e)

        xml = response.text

        action_result.add_debug_data(xml)

        # self.debug_print("REST Response", str(xml))

        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            self.save_progress(PAN_ERR_UNABLE_TO_PARSE_REPLY)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_UNABLE_TO_PARSE_REPLY, e)

        status = self._parse_response(response_dict, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        return action_result.get_status()

    def _get_first_allow_policy(self, action_result):

        ret_name = None
        result_data = action_result.get_data()

        if len(result_data) == 0:
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_PARSE_POLICY_DATA), ret_name)

        result_data = result_data[0]

        rules = result_data['rules']

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
            action = entry['action']
            if action is None:
                continue
            if isinstance(action, dict):
                action = action['#text']

            if action == 'allow':
                ret_name = entry['@name']
                break

        if ret_name is None:
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_ALLOW_POLICY_ENTRIES_FOUND), ret_name)

        return (action_result.set_status(phantom.APP_SUCCESS), ret_name)

    def _add_url_security_policy(self, vsys, action_result, type, name=None):

        element = SEC_POL_DEF_ELEMS

        sec_policy_name = SEC_POL_NAME.format(type=type)
        allow_rule_name = self._param.get(PAN_JSON_SEC_POLICY)

        self.debug_print("Creating Security Policy", sec_policy_name)

        if type != SEC_POL_URL_TYPE:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_CREATE_UNKNOWN_TYPE_SEC_POL)

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

            self.debug_print("Get Policies Action Result", policy_list_act_res)

            status, allow_rule_name = self._get_first_allow_policy(policy_list_act_res)

            if phantom.is_fail(status):
                return action_result.set_status(status, policy_list_act_res.get_message())

        self.debug_print("allow_rule_name", allow_rule_name)

        element += ACTION_NODE_ALLOW
        element += URL_PROF_SEC_POL_ELEM.format(url_prof_name=BLOCK_URL_PROF_NAME)
        element += APP_GRP_SEC_POL_ELEM.format(app_group_name="any")
        element += IP_GRP_SEC_POL_ELEM.format(ip_group_name="any")

        xpath = SEC_POL_XPATH.format(vsys=vsys, sec_policy_name=sec_policy_name)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        self.debug_print("_add_url_security_policy::data", data)

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

        self.debug_print("_add_url_security_policy::move data", data)

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

        self.debug_print("Creating Security Policy", sec_policy_name)

        if type == SEC_POL_URL_TYPE:
            # URL needs to be handled differently
            return self._add_url_security_policy(vsys, action_result, type, name)
        elif type == SEC_POL_IP_TYPE:
            element += ACTION_NODE_DENY
            element += APP_GRP_SEC_POL_ELEM.format(app_group_name="any")
            if use_source:
                element += IP_GRP_SEC_POL_ELEM_SRC.format(ip_group_name=block_ip_grp)
            else:
                element += IP_GRP_SEC_POL_ELEM.format(ip_group_name=BLOCK_IP_GROUP_NAME)
        elif type == SEC_POL_APP_TYPE:
            element += ACTION_NODE_DENY
            element += APP_GRP_SEC_POL_ELEM.format(app_group_name=name)
            element += IP_GRP_SEC_POL_ELEM.format(ip_group_name="any")
        else:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_CREATE_UNKNOWN_TYPE_SEC_POL)

        xpath = SEC_POL_XPATH.format(vsys=vsys, sec_policy_name=sec_policy_name)
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        self.debug_print("_add_security_policy::data", data)

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # move it to the top
        data = {'type': 'config',
                'action': 'move',
                'key': self._key,
                'xpath': xpath,
                'where': 'top'}

        self.debug_print("_add_security_policy::move data", data)

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

        self.debug_print("Commiting the config")

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
        job_id = result_data['job']

        self.debug_print("commit job id: ", job_id)

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
            job = result_data[0]['job']
            if job['status'] == 'FIN':
                break

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job['progress'])

            time.sleep(2)

        return action_result.get_status()

    def _unblock_url(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        self.debug_print("Removing the Blocked URL")

        # Add the block url, will create the url profile if not present
        block_url = param[PAN_JSON_URL]

        xpath = "{0}{1}".format(URL_PROF_XPATH.format(vsys=vsys, url_profile_name=BLOCK_URL_PROF_NAME),
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

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        self.debug_print("Adding the Block URL")
        # Add the block url, will create the url profile if not present
        block_url = param[PAN_JSON_URL]
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': URL_PROF_XPATH.format(vsys=vsys, url_profile_name=BLOCK_URL_PROF_NAME),
                'element': URL_PROF_ELEM.format(url=block_url)}

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

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        block_app = param[PAN_JSON_APPLICATION]

        xpath = "{0}{1}".format(APP_GRP_XPATH.format(vsys=vsys, app_group_name=BLOCK_APP_GROUP_NAME),
                self._get_app_del_elem_path(block_app))

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

    def _get_app_del_elem_path(self, app_name):

        try:
            version_list = self._device_version.split('.')
            major_version = int(version_list[0])
        except Exception as e:
            self.debug_print("Handled exp on version parsing", e)
            # return the default, which is known to work with the later versions
            return DEL_APP_XPATH.format(app_name=app_name)

        # Decide based on major version number
        if major_version <= 6:
            return DEL_APP_XPATH_VER6.format(app_name=app_name)

        return DEL_APP_XPATH.format(app_name=app_name)

    def _get_app_group_elem(self, app_name):

        try:
            version_list = self._device_version.split('.')
            major_version = int(version_list[0])
        except Exception as e:
            self.debug_print("Handled exp on version parsing", e)
            # return the default, which is known to work with the later versions
            return APP_GRP_ELEM.format(app_name=app_name)

        # Decide based on major version number
        if major_version <= 6:
            return APP_GRP_ELEM_VER6.format(app_name=app_name)

        return APP_GRP_ELEM.format(app_name=app_name)

    def _block_application(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        self.debug_print("Creating the Application Group")

        block_app = param[PAN_JSON_APPLICATION]

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': APP_GRP_XPATH.format(vsys=vsys, app_group_name=BLOCK_APP_GROUP_NAME),
                'element': self._get_app_group_elem(block_app)}

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

        name = "{0} {1}".format(rem_slash(ip), PHANTOM_ADDRESS_NAME)

        return name

    def _add_address(self, vsys, block_ip, action_result):

        type = None
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
            return (action_result.get_status(), name)

        # Try to figure out the type of ip
        if block_ip.find('/') != -1:
            type = 'ip-netmask'
        elif block_ip.find('-') != -1:
            type = 'ip-range'
        elif phantom.is_ip(block_ip):
            type = 'ip-netmask'
        elif phantom.is_hostname(block_ip):
            type = 'fqdn'
        else:
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT), name)

        name = self._get_addr_name(block_ip)

        address_xpath = IP_ADDR_XPATH.format(vsys=vsys, ip_addr_name=name)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': address_xpath,
                'element': IP_ADDR_ELEM.format(type=type, ip=block_ip, tag=tag)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return (action_result.get_status(), name)

        return (phantom.APP_SUCCESS, name)

    def _unblock_ip(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        # Create the ip addr name
        unblock_ip = param[PAN_JSON_IP]

        # check and pass to create policy
        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME

        addr_name = self._get_addr_name(unblock_ip)

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

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        vsys = param.get(PAN_JSON_VSYS, 'vsys1')

        # First create the ip
        self.debug_print("Adding the IP Group")

        block_ip = param[PAN_JSON_IP]

        # check and pass to create policy
        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME

        status, addr_name = self._add_address(vsys, block_ip, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

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

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add the address to the phantom address group
        data = {'type': 'config',
                'action': 'get',
                'key': self._key,
                'xpath': APP_LIST_XPATH}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        try:
            # Move things around, so that result data is an array of applications
            result_data = action_result.get_data()
            result_data = result_data.pop(0)
            result_data = result_data['application']['entry']
        except Exception as e:
            self.debug_print("Handled exception while parsing Applications response", e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse applications info response")

        action_result.update_summary({PAN_JSON_TOTAL_APPLICATIONS: len(result_data)})

        action_result.update_data(result_data)

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
            self.debug_print("Handled exception while parsing sw-version", e)
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
            message = "Version validation failed for App supported version '{0}'".format(version_regex)
            # self.save_progress(message)
            return action_result.set_status(phantom.APP_ERROR, message)

        self._device_version = device_version

        return phantom.APP_SUCCESS

    def validate_parameters(self, param):
        """This app does it's own validation
        """
        return phantom.APP_SUCCESS

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        self._param = param

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == self.ACTION_ID_BLOCK_URL:
            result = self._block_url(param)
        elif action == self.ACTION_ID_UNBLOCK_URL:
            result = self._unblock_url(param)
        elif action == self.ACTION_ID_BLOCK_APPLICATION:
            result = self._block_application(param)
        elif action == self.ACTION_ID_UNBLOCK_APPLICATION:
            result = self._unblock_application(param)
        elif action == self.ACTION_ID_BLOCK_IP:
            result = self._block_ip(param)
        elif action == self.ACTION_ID_UNBLOCK_IP:
            result = self._unblock_ip(param)
        elif action == self.ACTION_ID_LIST_APPS:
            result = self._list_apps(param)

        return result


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

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

    exit(0)
