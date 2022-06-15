#!/usr/bin/env python3
import requests
import json
import sys

####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         14 June 2022
# version:      1.0.0
####################################

# Global Variables - ADD CORRECT VALUES
tennant_id = 'Azure Directory (tenant) ID'
client_id = 'Azure Application (client) ID'
client_secret = 'Azure Client Secret'
ad_group_name = 'AD Group Name'



azure_base_url = "https://graph.microsoft.com/v1.0/groups"
azure_headers = {"Accept": "application/json", "Content-Type": "application/json"}

def getADAccessToken(client_id,client_secret):
    url = f"https://login.microsoftonline.com/{tennant_id}/oauth2/v2.0/token"
    payload = f'''
        client_id={client_id}
        &scope=https%3A%2F%2Fgraph.microsoft.com%2F.default
        &client_secret={client_secret}
        &grant_type=client_credentials
    '''
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, headers=headers, data=payload)
    if response is None:
        print("ERROR: Not able to login into Azure AD - no response!")
    if response.status_code != 200:
        print(f"Error getting access token - HTTP Status Code: {str(response.status_code)}")
    data = response.json()

    if "access_token" in data:
        azure_headers['Authorization'] = "Bearer " + data['access_token']
        return 0

    else:
        print("Unknown Error: Unable to gain access token for Azure AD")

def getAdGroupId(ad_group_name):
    url = azure_base_url
    checkForGroups = True

    while checkForGroups:
        response = requests.get(url, headers=azure_headers, verify= True)
        if response is None:
            log_msg = ("Error retrieving Azure AD Groups - no response!")
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = (f"Error retrieving Azure AD Groups - HTTP Status Code: {str(response.status_code)}")
            raise TypeError(log_msg)
        
        rawData = response.json()
        for group in rawData['value']:
            if ad_group_name == group['displayName']:
                return group['id']

        if '@odata.nextLink' in rawData:
            url = rawData['@odata.nextLink']
        else:
            log_msg = f"Group {ad_group_name} was not found in Azure AD"
            raise TypeError(log_msg)
        

def retrieveADUsers(ad_group_name):
    try:
        ad_group_id = getAdGroupId(ad_group_name)
    except TypeError as e:
        raise TypeError(e)
    except:
        log_msg = "Unknown Error retrieving AD groups!"
        raise TypeError(log_msg)

    url = f"{azure_base_url}/{ad_group_id}/members?$select=displayName,accountEnabled,mail,userPrincipalName,id"
    adUsers = []

    checkForUsers = True

    while checkForUsers:
        response = requests.get(url, headers=azure_headers, verify= True)
        if response is None:
            log_msg = ("Error retrieving Azure AD users - no response!")
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = (f"Error retrieving Azure AD users - HTTP Status Code: {str(response.status_code)}")
            raise TypeError(log_msg)

        rawData = response.json()
        if '@odata.nextLink' in rawData:
            url = rawData['@odata.nextLink']
        else:
            checkForUsers = False
        
        rawList = rawData['value']
        adUsers = adUsers + rawList
        print(f"completed page of AD Users. Total Users collected is {len(adUsers)}")
    
    return adUsers


def main():
    ad_users = {}
    getADAccessToken(client_id,client_secret)
    try:
        ad_results = retrieveADUsers(ad_group_name)
    except TypeError as e:
        print(e)
        print("script exiting....")
        raise SystemExit
    except:
        log_msg = ("Unknown Error: Failed to retrieve users from Azure AD")
        print(log_msg)
        print("script exiting....")
        raise SystemExit
    for ad_entry in ad_results:
        if ad_entry['displayName'] not in ad_users:
            try:
                ad_users[ad_entry['displayName']] = {
                    "accountEnabled": ad_entry['accountEnabled'],
                    "email": ad_entry['mail'],
                    "username": ad_entry['userPrincipalName']
                }
            except:
                log_msg = (f"Unexpected error: {sys.exc_info()[0]}")
                print(log_msg)
                ldap_capture_success = False
                continue
    for name, details in ad_users.items():
        print(name, details)

if __name__ == '__main__':
    main()