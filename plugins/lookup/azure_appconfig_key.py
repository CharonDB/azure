# Copyright (c) 2026 Charon De Beukelaer (@charondb)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
name: azure_appconfig_key
author:
    - Charon De Beukelaer (@charondb)
version_added: '3.13.0'
requirements:
    - azure-appconfiguration
short_description: Read key values from Azure App Configuration.
description:
  - This lookup returns the value of keys stored in Azure App Configuration.
  - This lookup uses App Configuration access keys or connection strings.
options:
    _terms:
        description:
          - Key name or a list of key names.
        required: True
    appconfigstore_url:
        description:
          - The App Configuration endpoint URL (for example, C(https://myappconfig.azconfig.io)).
        required: True
    use_msi:
        description:
          - MSI token autodiscover.
          - The default is to try MSI authentication first, then use auth_source, You can disable MSI entirely
            by setting this to False.
        default: true
    use_cli:
        description:
          - When I(use_cli=True), get the 'az login' credential authentication, default if false.
          - Deprecated, please use I(auth_source=cli) instead.
    cloud_type:
        description: Specify which cloud, such as C(azure), C(usgovcloudapi).
notes:
    - If ansible is running on Azure Virtual Machine with MSI enabled, client_id, secret and tenant are not required.
    - For enabling MSI on Azure VM, please refer to this doc https://docs.microsoft.com/en-us/azure/active-directory/managed-service-identity/
    - After enabling MSI on Azure VM, remember to grant access of the Key Vault to the VM by adding a new Acess Policy in Azure Portal.
    - If MSI is not enabled on ansible host, it's required to provide a valid service principal which has access to the app configuration store.
    - To authenticate via service principal, pass client_id, secret and tenant or set environment variables
      AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_TENANT_ID.
    - Authentication via C(az login) is also supported. Set I(use_cli=true) when using Azure CLI.
    - To use a plugin from a collection, please reference the full namespace, collection name, and lookup plugin name that you want to use.
extends_documentation_fragment:
    - azure.azcollection.azure_plugin
"""

EXAMPLE = """
- name: Look up secret when azure cli login
  debug:
    msg: msg: "{{ lookup('azure.azcollection.azure_rm_appconfig_key', 'testkey', appconfigstore_url=appconfig_uri, use_cli=true)}}"

"""

RETURN = """
  _raw:
    description: App Config content string
"""

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMAuth
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

try:
    import logging
    import requests
    from azure.appconfiguration import AzureAppConfigurationClient

except ImportError:
    pass

display = Display()

logger = logging.getLogger("azure.identity").setLevel(logging.ERROR)

class LookupModule(LookupBase):
    def _lookup_key(self, terms, appconfigstore_url, auth_source):
        
        tenant = self.get_option('tenant') 
        client_id = self.get_option('client_id')
        secret = self.get_option('secret')

        # Legacy use_cli will set auth_source to cli.
        if self.get_option('use_cli'):
            auth_source = 'cli'
        # If auth_source is auto but no client_id or secret passed in switch to cli
        if auth_source == 'auto':
            if any(v is None for v in [client_id, secret, tenant]):
                auth_source = 'cli'

        auth_options = dict(
            auth_source=auth_source,
            client_id=client_id,
            secret=secret,
            tenant=tenant,
            is_ad_resource=True
        )

        azure_auth = AzureRMAuth(**auth_options)

        client = AzureAppConfigurationClient(appconfigstore_url, azure_auth.azure_credential_track2)

        ret = []
        for term in terms:
            try:
                setting = client.get_configuration_setting(key=term).value
                ret.append(setting)
            except Exception:
                raise AnsibleError('Failed to fetch key {0} from {1}.'.format(term, client._endpoint))
        return ret

    def _lookup_key_non_msi(self, terms, appconfigstore_url, auth_source):
        # Backward-compatible path for non-MSI auth.
        return self._lookup_key(terms, appconfigstore_url, auth_source)

    def run(self, terms, variables, **kwargs):

        self.set_options(direct=kwargs)

        ret = []
        ## default auth_source is auto
        auth_source = self.get_option('auth_source')
        appconfigstore_url = self.get_option('appconfigstore_url')
        use_msi = self.get_option('use_msi')
        TOKEN_ACQUIRED = False
        token = None

        token_params = {
            'api-version': '2018-02-01',
            'resource': f"{appconfigstore_url}"
        }

        token_headers = {
            'Metadata': 'true'
        }

        if use_msi:
            try:
                token_res = requests.get('http://169.254.169.254/metadata/identity/oauth2/token',
                                         params=token_params,
                                         headers=token_headers,
                                         timeout=(3.05, 27))
                if token_res.ok:
                    token = token_res.json().get("access_token")
                    if token is not None:
                        TOKEN_ACQUIRED = True
                    else:
                        display.v('Successfully called MSI endpoint, but no token was available. Will use service principal if provided.')
                else:
                    display.v("Unable to query MSI endpoint, Error Code %s. Will use service principal if provided" % token_res.status_code)
            except Exception:
                display.v('Unable to fetch MSI token. Will use service principal if provided.')

        if appconfigstore_url is None:
            raise AnsibleError('Failed to get valid App Configuration store URL.')
        if TOKEN_ACQUIRED:
            appconfig_params = {'api-version': '2024-09-01'}
            appconfig_headers = {'Authorization': 'Bearer ' + token}
            for term in terms:
                try:
                    secret_res = requests.get(appconfigstore_url + '/kv/' + term, params=appconfig_params, headers=appconfig_headers)
                    ret.append(secret_res.json()["value"])
                except KeyError:
                    raise AnsibleError('Failed to fetch secret ' + term + ' from ' + appconfigstore_url + '.')
                except Exception:
                    raise AnsibleError('Failed to fetch secret ' + term + ' from ' + appconfigstore_url + ' via MSI endpoint.')
            return ret
        else:
            return self._lookup_key_non_msi(terms, appconfigstore_url, auth_source)