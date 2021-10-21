import requests
import urllib3
import json
import os
import sys
from typing import List, Text, Dict
from time import sleep
from copy import deepcopy
import configargparse
import logging

from ansible import constants as C
from ansible.parsing.vault import VaultLib
from ansible.cli import CLI
from ansible.parsing.dataloader import DataLoader
from pathlib import Path
import yaml

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

HTTPS_PORT = "443"

def my_custom_logger(logger_name, log_file, level=logging.info):
    """
    Method to return a custom logger with the given name and level
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)
    format_string = '%(asctime)s %(message)s'
    datefmt_string ='%m/%d/%Y %I:%M:%S %p'
    log_format = logging.Formatter(fmt=format_string, datefmt=datefmt_string)
    # Creating and adding the console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)
    # Creating and adding the file handler
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setFormatter(log_format)
    logger.addHandler(file_handler)
    return logger


def get_inventory(inventory_file: Text) -> Dict:

    with open(inventory_file) as f:
        inventory = yaml.safe_load(f)

    if inventory.get("all") is None:
        raise Exception(f"{inventory_file} exists, but is not properly formatted")

    if inventory['all'].get('children') is None:
        raise Exception(f"{inventory_file} exists, but is not properly formatted")

    return inventory['all']['children']


def get_device_credentials(vault_file: Text, vault_pass_file: Text) -> Dict:

    loader = DataLoader()
    vault_secret = CLI.setup_vault_secrets(
        loader=loader,
        vault_ids=C.DEFAULT_VAULT_IDENTITY_LIST,
        vault_password_files=[vault_pass_file]
    )
    vault = VaultLib(vault_secret)
    vault_data = vault.decrypt(open(vault_file).read())

    vault_values = vault_data.decode().split("\n")
    creds = {}
    for value in vault_values:
        if value == "":
            continue
        _key, _val = value.replace(" ", "").split(":")
        if _key == 'svc_account_password':
            creds.update({"password": _val})
        elif _key == 'svc_account_user':
            creds.update({"username": _val})

        creds.update({_key:_val})

    return(creds)


def get_policy_components(
        device_name: Text, device_ip: Text, domain: Text, url: Text, api_key: Text, output_path: Text, logger, 
) -> None:

    # Notes:
    # "show-packages" gets the policy package list
    #
    # "show-package"  gets a specific policy package. this will have a list of access-layers, which needs to get fed
    # into `show-access-rulebase` API call to get details of the layer (sections, inline layers, rules)
    #
    # "show-access-rulebase" should return everything we need in terms of access rules.
    # According to their API docs:
    # Shows the entire Access Rules layer. This layer is divided into sections. An Access Rule may be within a
    # section, or independent of a section (in which case it is said to be under the "global" section).
    # The reply features a list of objects. Each object may be a section of the layer, with all its rules in,
    # or a rule itself, for the case of rules which are under the global section. An optional "filter" field
    # may be added in order to filter out only those rules that match a search criteria. So we don't need to
    # worry about using `show-access-layers`, `show-access-sections` or `show-access-rule` APIs
    #
    # "show-nat-rulebase" should return everything we need in terms of nat rules. it needs a package name as input
    # According to their API docs:
    # Shows the entire NAT Rules layer. This layer is divided into sections. A NAT Rule may be within a section,
    # or independent of a section (in which case it is said to be under the "global" section). There are two
    # types of sections: auto generated read only sections and general sections which are created manually.
    # The reply features a list of objects. Each object may be a section of the layer, within which its rules
    # may be found, or a rule itself, for the case of rules which are under the global section. An optional
    # "filter" field may be added in order to filter out only those rules that match a search criteria.
    # So we don't need to worry about using `show-nat-section` or `show-nat-rule` APIs

    # retrieve list of packages
    logger.info(f"Getting list of packages in domain {domain}")
    packages_list = api_call(url, "show-packages", {"details-level": "full"}, api_key, pagination=True, logger=logger)
    save_output_to_file(
        device_name, domain, "show-packages", packages_list, output_path
    )

    # retrieve details of each package

    # packages_list can have multiple package dictionaries embedded in it, due to the nature of data collection
    # and pagination. So have to loop through all of the dictionaries in it and find the list of packages in
    # each entry
    for packages in packages_list:
        for package in packages['packages']:
            logger.debug(f"Retrieving details for package {package} in domain {domain} on {device_name}")
            pkg_name = package['name']
            pkg_uid = package['uid']
            pkg_details = api_call(url, "show-package", {"name": pkg_name, "details-level": "full"},
                                   api_key, pagination=False, logger=logger)
            save_output_to_package_file(
                device_name, domain, pkg_name, "show-package", pkg_details,
                output_path)

            logger.debug(f"Package {pkg_name} details: {pkg_details}")
            if len(pkg_details) != 1:
                # API doesn't support pagination so results is a list with a single element
                exc_str = f"Call to get {pkg_name} details returned list that is not a single element"
                logger.error(exc_str)
                raise Exception(exc_str)

            access_layers = []  # collect output of `show-access-rulebase` for each layer in package and append here
            _acc_layers = pkg_details[0].get("access-layers", [])
            for _acc_layer in _acc_layers:
                acc_layer_name = _acc_layer['name']
                logger.info(f"Retrieving access-rule-base {acc_layer_name} in package {pkg_name} "
                             f"in domain {domain} on {device_name}")
                access_rulebase = api_call(url, "show-access-rulebase",
                                           {"name": acc_layer_name, "details-level": "full", "use-object-dictionary": True},
                                           api_key, pagination=True, logger=logger)
                access_layers.extend(access_rulebase)

            save_output_to_package_file(
                device_name, domain, pkg_name, "show-access-rulebase", access_layers, output_path
            )

            logger.info(f"Retrieving nat-rulebase in package {pkg_name} in domain {domain} on {device_name}")
            nat_rules = api_call(url, "show-nat-rulebase",
                                 {"package": pkg_name, "details-level": "full", "use-object-dictionary": True},
                                api_key,  pagination=True, logger=logger)

            save_output_to_package_file(
                device_name, domain, pkg_name, "show-nat-rulebase", nat_rules, output_path
            )


def get_request_components_management_solo(api_version: Text) -> List[Dict]:
    """
    :return: list of dictionary containing following solo request components for checkpoint management server
        - resource: e.g. 'show-packages'
        - body: e.g {"details-level": "full"}
    """

    query = {
        "1.5": [
            # Network Objects
            {"show-hosts": {"details-level": "full"}},
            {"show-networks": {"details-level": "full"}},
            {"show-groups": {"details-level": "full"}},
            {"show-address-ranges": {"details-level": "full"}},
            # Service & Applications
            {"show-services-tcp": {"details-level": "full"}},
            {"show-services-udp": {"details-level": "full"}},
            {"show-services-icmp": {"details-level": "full"}},
            {"show-services-sctp": {"details-level": "full"}},
            {"show-services-other": {"details-level": "full"}},
            {"show-service-groups": {"details-level": "full"}},
            # Misc
            {"show-gateways-and-servers": {"details-level": "full"}},
            {"show-objects": {"details-level": "full"}},
        ],
        "1.7": [
            # Network Objects
            {"show-hosts": {"details-level": "full"}},
            {"show-networks": {"details-level": "full"}},
            {"show-groups": {"details-level": "full"}},
            {"show-security-zones": {"details-level": "full"}},
            # Service & Applications
            {"show-services-tcp": {"details-level": "full"}},
            {"show-services-udp": {"details-level": "full"}},
            {"show-services-icmp": {"details-level": "full"}},
            {"show-services-sctp": {"details-level": "full"}},
            {"show-services-other": {"details-level": "full"}},
            {"show-service-groups": {"details-level": "full"}},
            {"show-services-dce-rpc": {"details-level": "full"}},
            {"show-services-rpc": {"details-level": "full"}},
            {"show-services-gtp": {"details-level": "full"}},
            {"show-services-citrix-tcp": {"details-level": "full"}},
            {"show-services-compound-tcp": {"details-level": "full"}},
            # Misc
            {"show-gateways-and-servers": {"details-level": "full"}},
            {"show-objects": {"details-level": "full"}},
        ],
    }

    return query[api_version]


def api_call(in_url: Text, resource: Text, body: Dict, api_key: Text, pagination: bool, logger, ) -> List:


    url = f"{in_url}/{resource}"

    # a single API call will not contain all resources, so we need to check the response to determine when all
    # records have been retrieved. to do so, we need to set the limit (default) and offset (default 0) in the request
    #
    # the results will have a from, to and total value. compare the total against limit to determine if
    # we need to continue to loop.

    results = []
    has_more = True
    offset = 0 # DO NOT CHANGE
    limit = 500 # default is 50, max value is 500
    sleep_counter = 0
    max_sleep = 1
    params = body
    loop_counter = 0

    while has_more is True:

        headers = {"Content-Type": "application/json", "X-chkp-sid": api_key}

        if pagination is True:
            params.update({
                "limit": limit,
                "offset": offset
            })

        logger.info(f"Attempting to retrieve {url} with params {params}")

        r = requests.post(
        url, data=json.dumps(params), headers=headers, verify=False)

        if r.ok:
            response = r.json()
            logger.info(f"Data Keys: {response.keys()}\n")
            logger.info(f"Data: Total: {response.get('total', None)}, From:{response.get('from', None)}, To:{response.get('to', None)}\n")
            if pagination is False:
                logger.info(f"API call doesn't support pagination, returning response as list element 0")
                return [response]
                # if API doesn't support pagination, there is no total key and all the data comes back in a single call
            elif response['total'] == 0:
                has_more = False
                return results
            elif response['total'] < limit:
                has_more = False
                logger.info(f"No more results left to retrieve, ending loop after {loop_counter} iterations")

            if response.get('to') is None:
                # some API calls will NOT set total to 0 if you offset in your request is > total
                # so have to also check if the `to` value is None

                has_more = False
                logger.info(f"No more results left to retrieve, ending loop after {loop_counter} iterations")
                return results
            else:
                offset = response.get('to')
                sleep_counter = 0
                logger.debug(f"Results: {response}")
                results.append(deepcopy(response))
                logger.info(f"Loop count: {loop_counter}")
                loop_counter += 1
        else:
            exc_str = f"API call to {url} failed. Request payload {params}, response code {r.status_code}, text {r.text}\n"
            error = json.loads(r.text)
            if error['code'] == 'err_too_many_requests':
                # assuming failure due to API rate limiting, so sleep and try again
                # implement a sleep counter after which we raise an exception
                if sleep_counter == max_sleep:
                    logger.error(exc_str)
                    raise Exception(exc_str)
                else:
                    sleep_counter += 1
                    logger.info("Sleeping for 5 seconds before re-trying last call")
                    sleep(5)
                    continue
            else:
                logger.info("Ignoring error and continuing")
                logger.error(exc_str)
                has_more = False
                # figure out how to gracefully handle r.text.code == generic_err_command_not_found

    return results


def get_api_versions(device_name: Text, device_ip: Text, credentials: Dict, output_path: Text, logger, ) -> Text:

    results = []
    url = get_url(device_name, HTTPS_PORT)
    api_key = create_session(
        url,
        "login",
        {"user": credentials['username'], "password": credentials['password'],},
        "",
        logger,
    )

    if api_key is not None:
        logger.info(f"Login successful. Retrieved API key: {api_key}")
    else:
        exc_str = f"Unable to log into server and retrieve API key. api_call returned None"
        logger.error(exc_str)
        raise Exception(exc_str)

    resource = "show-api-versions"
    params = {}
    headers = {"Content-Type": "application/json", "X-chkp-sid": api_key}

    resource_url = f"{url}/{resource}"
    logger.info(f"Attempting to retrieve {resource_url} with params {params}")

    r = requests.post(
    resource_url, data=json.dumps(params), headers=headers, verify=False)

    if r.ok:
        response = r.json()
        logger.debug(f"Data Keys: {response.keys()}\n")
        logger.info(f"Current API version: {response.get('current-version', None)}\n")
        logger.debug(f"Supported API versions: {response.get('supported-versions', None)}\n")
        api_version = response.get('current-version', None)
        results.append(response)
    else:
        # should see if we can different the error types based on the text
        # want to sleep only if error is err_too_many_requests
        exc_str = f"API call to {url} failed. Request payload {params}, response code {r.status_code}, text {r.text}\n"
        logger.error(exc_str)
        raise Exception(exc_str)


    save_output_to_file(
        device_name, "Parent", resource, results, output_path,
    )

    # log-out
    end_session(url, "logout", {}, api_key, logger)

    if api_version is None:
        exc_str = f"Empty API version returned by show-api-versions API call {results}"
        logger.error(exc_str)
        raise Exception(exc_str)

    return api_version


def create_session(url: Text, resource: Text, body: Dict, api_key: Text, logger,) -> Text:
    """
    :param url:
    :param resource:
    :param body:
    :param api_key:
    :return: output of REST API Post call
    """

    url = f"{url}/{resource}"

    params = body
    # Header for API Key
    headers = {"Content-Type": "application/json"}

    r = requests.post(
    url, data=json.dumps(params), headers=headers, verify=False)

    if r.ok:
        try:
            api_key = r.json()['sid']
            return api_key
        except:
            exc_str = f"Login succeeded, but failed to retrieve api-key. Return status {r}"
            logger.error(exc_str)
    else:
        exc_str = f"Failed to login and retrieve api-key. Return status {r}"
        logger.error(exc_str)


def end_session(url: Text, resource: Text, body: Dict, api_key: Text,logger, ) -> None:
    """
    :param url:
    :param resource:
    :param body:
    :param api_key:
    :return: None
    """

    url = f"{url}/{resource}"
    params = body

    logger.info(f"Attempting to logout with {url} with params {params}")

    headers = {"Content-Type": "application/json", "X-chkp-sid": api_key}

    r = requests.post(
        url, data=json.dumps(params), headers=headers, verify=False)

    if r.ok:
        logger.info("Log-out successful")
    else:
        logger.error(f"{r}")
        exc_str = "Session Logout failed"
        logger.error(exc_str)
        raise Exception(exc_str)


def get_url(device_name: Text, port: Text) -> Text:
    """
    :param device_name:
    :param port:
    :return: URL for checkpoint manager
    """
    return f"https://{device_name}:{port}/web_api"


def save_output_to_file(
        device_name: Text, domain: Text, resource: Text, output: List, file_path: Text
) -> None:
    """
    :param device_name:
    :param domain:
    :param resource:
    :param output:
    :param file_path:
    :return: Save REST API call output to file
    """
    file_path = f"{file_path}/{device_name}/{domain}/{resource}.json"
    save_output_to_file_path(file_path, output)


def save_output_to_package_file(
        device_name: Text, domain: Text, package: Text, resource: Text, output: List, file_path: Text
) -> None:
    """
    :param device_name:
    :param domain:
    :param package:
    :param resource:
    :param output:
    :param file_path:
    :return: Save REST API call output to file
    """
    file_path = f"{file_path}/{device_name}/{domain}/{package}/{resource}.json"
    save_output_to_file_path(file_path, output)


def save_output_to_file_path(file_path: Text, output: List) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(output, f)


def get_domain_list(device_name: Text, device_ip: Text, credentials: Dict, output_path: Text, logger, ) -> List:

    domain_list = []
    url = get_url(device_name, HTTPS_PORT)
    api_key = create_session(
        url,
        "login",
        {"user": credentials['username'], "password": credentials['password'],},
        "",
        logger,
    )

    if api_key is not None:
        logger.info(f"Login successful. Retrieved API key: {api_key}")
    else:
        exc_str = f"Unable to log into server and retrieve API key. api_call returned None"
        logger.error(exc_str)
        raise Exception(exc_str)

    logger.info(f"Retrieving show-domains for device {device_name}")

    resource = "show-domains"
    body = {"details-level": "full"}
    output = api_call(
        url, resource, body, api_key, pagination=True, logger=logger
    )

    save_output_to_file(
        device_name, "Parent", resource, output, output_path,
    )

    logger.info(f"Retrieved show-domains for device {device_name}")
    logger.debug(f"show-domains output:\n {output}")
    for entry in output:
        domain_objects = entry.get("objects", [])
        for domain_object in domain_objects:
            domain_list.append(domain_object.get("name"))

    # log-out
    end_session(url, "logout", {}, api_key, logger)

    return domain_list


def get_api_data(device_name: Text, device_ip: Text, credentials: Dict, output_path: Text, logger, ) -> None:

    # todo: add handling to use device_ip if device_name is not resolvable via DNS
    api_version = get_api_versions(device_name, device_ip, credentials, output_path, logger)

    domains = get_domain_list(device_name, device_ip, credentials, output_path, logger)

    MAX_LOGIN_RETRIES = 3
    for domain in domains:
        login_retries = 0
        TRY_LOGIN = True
        while TRY_LOGIN:
            logger.info(f"Connecting to {device_name} domain {domain}")
            url = get_url(device_name, HTTPS_PORT)
            api_key = create_session(
                url,
                "login",
                {"user": credentials['username'], "password": credentials['password'], "domain": domain},
                "",
                logger,
            )
            if api_key is not None:
                logger.info(f"Login successful. Retrieved API key: {api_key}")
                TRY_LOGIN = False
            elif login_retries == MAX_LOGIN_RETRIES:
                exc_str = f"Unable to log into server domain {domain} and retrieve API key. api_call returned None."
                logger.error(exc_str)
                TRY_LOGIN = False
            else:
                login_retries += 1
                sleep(5)

        if api_key is not None:
            # retrieve all of the policy packages and associated data
            get_policy_components(device_name, device_ip, domain, url, api_key, output_path, logger)

            # retrieve data that is not embedded within the policy packages
            for request_component in get_request_components_management_solo(api_version):
                for resource, body in request_component.items():
                    output = api_call(
                        url, resource, body, api_key, pagination=True, logger=logger
                    )
                    save_output_to_file(
                        device_name, domain, resource, output, output_path,
                    )

            # logout
            end_session(url, "logout", {}, api_key, logger)


def main():

    parser = configargparse.ArgParser()
    parser.add_argument("--inventory", help="Absolute path to inventory file to use", required=True)
    parser.add_argument("--output_dir", help="Absolute path to directory where results are to be written",
                        required=True)
    parser.add_argument("--debug", help="set log_level to DEBUG instead of INFO",
                        action='store_true')
    parser.add_argument("--vault", help="Vault file to use",
                        required=True)
    parser.add_argument("--vault-password-file", help="Vault passowrd file to use",
                        required=True)
    parser.add_argument("--max-threads", help="Set max threads for data collection. Default = 10, Maximum is 100",
                        type=int, default=10, choices=range(1,101))

    args = parser.parse_args()

    # set log level
    DEBUG = args.debug
    log_level = logging.INFO
    if DEBUG:
        log_level = logging.DEBUG

    # check if inventory file exists
    # inventory must be a valid ansible YAML inventory with this hierarchy
    # example:
    #
    # all:
    #   children:
    #     checkpoint_mgmt:
    #       vars:
    #         ansible_connection: local
    #         device_os: checkpoint_mgmt
    #       hosts:
    #         fake11: null
    #         fake12: null

    inv_file = args.inventory
    if Path(inv_file).exists():
        inventory = get_inventory(inv_file)
    else:
        raise Exception(f"{inv_file} does not exist")

    # check if output directory exists
    output_dir = args.output_dir
    if not Path(output_dir).exists() or not Path(output_dir).is_dir():
        raise Exception(f"{output_dir} does not exist or is not a directory")

    # retrieve device credentials - username and password
    # expected keys in vault are `svc_account_user` and `svc_account_password`
    # which will get mapped to `username` and `password` respectively
    # note: code assumes only a single account to connect to all devices
    vault_file = args.vault
    vault_pass_file = args.vault_password_file
    credentials = get_device_credentials(vault_file, vault_pass_file)
    if credentials.get("username") is None or credentials.get("password") is None:
        raise Exception("Unable to retrieve credentials from Ansible Vault")

    max_threads = args.max_threads
    pool = ThreadPoolExecutor(max_threads)
    future_list = []

    start_time = datetime.now()
    print(f"###Starting Checkpoint manager data collection: {start_time}")

    for grp, grp_data in inventory.items():
        device_os = grp_data['vars'].get('device_os') 
        if device_os is None or device_os != 'checkpoint_mgmt':
            continue

        for device_name, device_params in grp_data.get('hosts').items():
            log_file = f"{output_dir}/{device_name}/cp_manager.log"
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
            except:
                exc_str = f"Could not create directory for log_file {log_file}"
                raise Exception(exc_str)

            logger = my_custom_logger(device_name, log_file, log_level)
            logger.info(f"Starting data collection for {device_name}")
            logger.debug(f"Group {grp}, Group_data {grp_data}")

            # REST API calls
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            if device_params is None:
                device_ip = None
            else:
                device_ip = device_params.get("ansible_host")
            # code assumes DNS entry exists for the device name that is in the inventory
            # code also assumes the use of standard HTTPS_PORT (443) and no need for a proxy
            # device in the middle.
            future = pool.submit(get_api_data, device_name=device_name,
                                 device_ip=device_ip, credentials=credentials,
                                 output_path=output_dir, logger=logger)

            future_list.append(future)

    count = 0
    for future in as_completed(future_list):
        try:
            data = future.result()
        except Exception as exc:
            print(f"Exception generated: \n {exc}")
        print(f"Finished device number {count}")
        count += 1

    end_time = datetime.now()
    print(f"###Completed Checkpoint manager data collection collection: {start_time}")
    print(f"###Total time taken: {end_time - start_time}")


if __name__ == "__main__":
    main()
