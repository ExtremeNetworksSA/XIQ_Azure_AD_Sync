#!/usr/bin/env python3
import logging
import os
import inspect
import sys
import requests

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from app.logger import logger

####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         8 July 2026
# version:      3.0.1
####################################

logger = logging.getLogger('XIQ-AD-PPSK_Sync.azure_api')

PATH = current_dir
class AzureAPIFailedException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class AzureAPI:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.graph_api_url = "https://graph.microsoft.com/v1.0"
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}

    def __get_access_token(self):
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(self.token_url, headers=headers,data=payload)
        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            raise AzureAPIFailedException(f"Failed to obtain access token: {response.text}")

    def retrieveADUsers(self, ad_group_id):
        access_token = self.__get_access_token()
        self.headers['Authorization'] = f'Bearer {access_token}'
        url = f"{self.graph_api_url}/groups/{ad_group_id}//transitiveMembers?$select=displayName,accountEnabled,mail,userPrincipalName,id"

        adUsers = []

        checkForUsers = True

        while checkForUsers:
            response = requests.get(url, headers=self.headers, verify= True)
            if response is None:
                log_msg = ("Error retrieving Azure AD users - no response!")
                logger.error(log_msg)
                raise AzureAPIFailedException(log_msg)
            elif response.status_code != 200:
                log_msg = (f"Error retrieving Azure AD users - HTTP Status Code: {str(response.status_code)}")
                logger.error(log_msg)
                logger.warning(f"{response.json()}")
                raise AzureAPIFailedException(log_msg)
            rawData = response.json()
            if '@odata.nextLink' in rawData:
                url = rawData['@odata.nextLink']
            else:
                checkForUsers = False      
            rawList = rawData['value']
            adUsers = adUsers + rawList
            print(f"completed page of AD Users. Total Users collected is {len(adUsers)}")  
        return adUsers