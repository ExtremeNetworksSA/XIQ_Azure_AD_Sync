#!/usr/bin/env python3
import json
import requests
import sys
import os
import logging

####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         3 Oct 2024
# version:      1.1.2
####################################


# Global Variables - ADD CORRECT VALUES
tenant_id = 'Azure Directory (tenant) ID'
client_id = 'Azure Application (client) ID'
client_secret = 'Azure Client Secret'


#XIQ_username = "enter your ExtremeCloudIQ Username"
#XIQ_password = "enter your ExtremeCLoudIQ password"
####OR###
## TOKEN permission needs - enduser, pcg:key
XIQ_token = "****"

group_roles = [
    # AD GROUP Object ID, XIQ group ID
    ("AD Group Object ID", "XIQ User Group ID"),
    ("AD Group Object ID", "XIQ User Group ID")
]

PCG_Enable = False

PCG_Maping = {
    "XIQ User Group ID" : {
        "UserGroupName": "XIQ User Group Name",
        "policy_id": "Network Policy ID associated with PCG",
         "policy_name": "Network Policy name associated with PCG"
    }
}



#-------------------------
# logging
PATH = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename='{}/XIQ-Azure-AD-PPSK-sync.log'.format(PATH),
    filemode='a',
    level=os.environ.get("LOGLEVEL", "INFO"),
    format= '%(asctime)s: %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)

xiq_base_url = "https://api.extremecloudiq.com"
xiq_headers = {"Accept": "application/json", "Content-Type": "application/json"}

azure_base_url = "https://graph.microsoft.com/v1.0/groups"
azure_headers = {"Accept": "application/json", "Content-Type": "application/json"}

def getADAccessToken(client_id,client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = f'''
        client_id={client_id}
        &scope=https%3A%2F%2Fgraph.microsoft.com%2F.default
        &client_secret={client_secret}
        &grant_type=client_credentials
    '''
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, headers=headers, data=payload)
    if response is None:
        log_msg=("ERROR: Not able to login into Azure AD - no response!")
        logging.error(log_msg)
        raise TypeError(log_msg)
    if response.status_code != 200:
        log_msg=(f"Error getting access token - HTTP Status Code: {str(response.status_code)}")
        logging.error(log_msg)
        raise TypeError(log_msg)
    data = response.json()

    if "access_token" in data:
        azure_headers['Authorization'] = "Bearer " + data['access_token']
        return 0

    else:
        log_msg("Unknown Error: Unable to gain access token for Azure AD")
        logging.error(log_msg)
        raise TypeError(log_msg)


def retrieveADUsers(ad_group_id):
    url = f"{azure_base_url}/{ad_group_id}/transitiveMembers?$select=displayName,accountEnabled,mail,userPrincipalName,id"
    adUsers = []

    checkForUsers = True

    while checkForUsers:
        response = requests.get(url, headers=azure_headers, verify= True)
        if response is None:
            log_msg = ("Error retrieving Azure AD users - no response!")
            logging.error(log_msg)
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = (f"Error retrieving Azure AD users - HTTP Status Code: {str(response.status_code)}")
            logging.error(log_msg)
            logging.warning(f"{response.text}")
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


def getAccessToken(XIQ_username, XIQ_password):
    url = xiq_base_url + "/login"
    payload = json.dumps({"username": XIQ_username, "password": XIQ_password})
    response = requests.post(url, headers=xiq_headers, data=payload)
    if response is None:
        log_msg = "ERROR: Not able to login into ExtremeCloudIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    if response.status_code != 200:
        log_msg = f"Error getting access token - HTTP Status Code: {str(response.status_code)}"
        logging.error(f"{log_msg}")
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    data = response.json()

    if "access_token" in data:
        #print("Logged in and Got access token: " + data["access_token"])
        xiq_headers["Authorization"] = "Bearer " + data["access_token"]
        return 0

    else:
        log_msg = "Unknown Error: Unable to gain access token"
        logging.warning(log_msg)
        raise TypeError(log_msg)


def createPPSKuser(name,mail, usergroupID):
    url = xiq_base_url + "/endusers"

    payload = json.dumps({"user_group_id": usergroupID ,"name": name,"user_name": name,"password": "", "email_address": mail, "email_password_delivery": mail})

    response = requests.post(url, headers=xiq_headers, data=payload, verify=True)
    if response is None:
        log_msg = "Error adding PPSK user - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)

    elif response.status_code != 200:
        log_msg = f"Error adding PPSK user {name} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)

    elif response.status_code ==200:
        logging.info(f"successfully created PPSK user {name}")
        print(f"successfully created PPSK user {name}")
        return True


def retrievePPSKUsers(pageSize, usergroupID):
    page = 1
    pageCount = 1
    firstCall = True

    ppskUsers = []

    while page <= pageCount:
        url = xiq_base_url + "/endusers?page=" + str(page) + "&limit=" + str(pageSize) + "&user_group_ids=" + usergroupID

        # Get the next page of the ppsk users
        response = requests.get(url, headers=xiq_headers, verify = True)
        if response is None:
            log_msg = "Error retrieving PPSK users from XIQ - no response!"
            logging.error(log_msg)
            raise TypeError(log_msg)

        elif response.status_code != 200:
            log_msg = f"Error retrieving PPSK users from XIQ - HTTP Status Code: {str(response.status_code)}"
            logging.error(log_msg)
            logging.warning(f"\t\t{response.json()}")
            raise TypeError(log_msg)

        rawList = response.json()
        ppskUsers = ppskUsers + rawList['data']

        if firstCall == True:
            pageCount = rawList['total_pages']
        print(f"completed page {page} of {rawList['total_pages']} collecting PPSK Users")
        page = rawList['page'] + 1 
    return ppskUsers


def deleteUser(userId):
    url = xiq_base_url + "/endusers/" + str(userId)
    response = requests.delete(url, headers=xiq_headers, verify=True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    elif response.status_code == 200:
        return 'Success', str(userId)
    

def addUserToPcg(policy_id, name, email, user_group_name):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                  "users": [
                    {
                      "name": name,
                      "email": email,
                      "user_group_name": user_group_name
                    }
                  ]
                })
    response = requests.post(url, headers=xiq_headers, data=payload, verify=True)
    if response is None:
        log_msg = f"- no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    elif response.status_code == 200:
        return 'Success'


def retrievePCGUsers(policy_id):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    response = requests.get(url, headers=xiq_headers, verify = True)
    if response is None:
        log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 200:
        log_msg = f"Error retrieving PCG users for policy id {policy_id} from XIQ - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response.json()}")
        raise TypeError(log_msg)
    rawList = response.json()
    return rawList


def deletePCGUsers(policy_id, userId):
    url = xiq_base_url + "/pcgs/key-based/network-policy-" + str(policy_id) + "/users"
    payload = json.dumps({
                    "user_ids": [
                                    userId
                                ]
                })
    response = requests.delete(url, headers=xiq_headers, data=payload, verify = True)
    if response is None:
        log_msg = f"Error deleting PPSK user {userId} - no response!"
        logging.error(log_msg)
        raise TypeError(log_msg)
    elif response.status_code != 202:
        log_msg = f"Error deleting PPSK user {userId} - HTTP Status Code: {str(response.status_code)}"
        logging.error(log_msg)
        logging.warning(f"\t\t{response}")
        raise TypeError(log_msg)
    elif response.status_code == 202:
        return 'Success'



def main():
    if 'XIQ_token' not in globals():
        try:
            login = getAccessToken(XIQ_username, XIQ_password)
        except TypeError as e:
            print(e)
            raise SystemExit
        except:
            log_msg = "Unknown Error: Failed to generate token"
            logging.error(log_msg)
            print(log_msg)
            raise SystemExit     
    else:
        xiq_headers["Authorization"] = "Bearer " + XIQ_token
 
    ListOfADgroups, ListOfXIQUserGroups = zip(*group_roles)

    # Collect PSK users
    ppsk_users = []
    for usergroupID in ListOfXIQUserGroups:
        try:
            ppsk_users += retrievePPSKUsers(100,usergroupID)
        except TypeError as e:
            print(e)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
        except:
            log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
            logging.error(log_msg)
            print(log_msg)
            print("script exiting....")
            # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            raise SystemExit
    log_msg = ("Successfully parsed " + str(len(ppsk_users)) + " XIQ users")
    logging.info(log_msg)
    print(f"{log_msg}\n")

    # Generate Azure AD token
    try:
        getADAccessToken(client_id,client_secret)
    except TypeError as e:
        log_msg = f"Failed to Authenticate with Axure AD - {e}"
        logging.error(log_msg)
        print(log_msg)
        print("script is exiting....")
        raise SystemExit
    except:
        log_msg = "Failed to Authenticate with Azure AD - Unknown reason"
        logging.error(log_msg)
        print(log_msg)
        print("script is exiting....")
        raise SystemExit
    # Collect Azure AD Users
    ad_users = {}
    ad_capture_success = True
    for ad_group_id,xiq_user_role in group_roles:
        try:
            ad_results = retrieveADUsers(ad_group_id)
        except TypeError as e:
            print(e)
            print("script exiting....")
            raise SystemExit
        except:
            log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
            print(log_msg)
            print("script exiting....")
            raise SystemExit

        for ad_entry in ad_results:
            if ad_entry['@odata.type'] == '#microsoft.graph.group':
                logging.info(f"Found {ad_entry['displayName']} as a nested group. Skipping entry")
                continue
            if ad_entry['displayName'] not in ad_users:
                try:
                    ad_users[ad_entry['displayName']] = {
                        "accountEnabled": ad_entry['accountEnabled'],
                        "email": ad_entry['mail'],
                        "username": ad_entry['userPrincipalName'],
                        "xiq_role": xiq_user_role
                    }
                except:
                    log_msg = (f"Unexpected error: {sys.exc_info()}")
                    print(log_msg)
                    ad_capture_success = False
                    continue
    log_msg = "Successfully parsed " + str(len(ad_users)) + " Azure AD users"
    logging.info(log_msg)
    print(f"{log_msg}\n")

    # Track Error counts
    ppsk_create_error = 0
    pcg_create_error = 0
    ppsk_del_error = 0
    pcg_del_error = 0

    # Create PPSK Users
    ad_disabled = []
    for name, details in ad_users.items():
        user_created = False
        if details['email'] == None:
            log_msg = (f"User {name} doesn't have an email set and will not be created in xiq")
            logging.warning(log_msg)
            print(log_msg)
            continue
        if not any(d['user_name'] == name for d in ppsk_users) and details['accountEnabled'] == True:
            try:
                user_created = createPPSKuser(name, details["email"], details['xiq_role'])
            except TypeError as e:
                log_msg = f"failed to create {name}: {e}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            except:
                log_msg = f"Unknown Error: Failed to create user {name} - {details['email']}"
                logging.error(log_msg)
                print(log_msg)
                ppsk_create_error+=1
            if PCG_Enable == True and user_created == True and str(details['xiq_role']) in PCG_Maping:
                ## add user to PCG if PCG is Enabled
                policy_id = PCG_Maping[details['xiq_role']]['policy_id']
                policy_name = PCG_Maping[details['xiq_role']]['policy_name']
                user_group_name = PCG_Maping[details['xiq_role']]['UserGroupName']
                email = details["email"]
                result = ''
                try:
                    result = addUserToPcg(policy_id, name, email, user_group_name)
                except TypeError as e:
                    log_msg = f"failed to add {name} to pcg {policy_name}: {e}"
                    logging.error(log_msg)
                    print(log_msg)
                    pcg_create_error+=1
                except:
                    log_msg = f"Unknown Error: Failed to add user {name} - {details['email']} to pcg {policy_name}"
                    logging.error(log_msg)
                    print(log_msg)
                    pcg_create_error+=1
                if result == 'Success':
                    log_msg = f"User {name} - was successfully add to pcg {policy_name}."
                    logging.info(log_msg)
                    print(log_msg)

        elif details['accountEnabled'] == False:
            ad_disabled.append(name)
    
    # Remove disabled accounts from ad users
    for name in ad_disabled:
        logging.info(f"User {name} is disabled in Azure AD.")
        del ad_users[name]
    
    if PCG_Enable == True:
        pcg_capture_success = True
        # Collect PCG Users if PCG is Enabled
        PCGUsers = []
        for policy in PCG_Maping:
            policy_id = PCG_Maping[policy]['policy_id']

            try:
                PCGUsers += retrievePCGUsers(policy_id)
            except TypeError as e:
                print(e)
                pcg_capture_success = False
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
            except:
                log_msg = ("Unknown Error: Failed to retrieve users from XIQ")
                logging.error(log_msg)
                print(log_msg)
                pcg_capture_success = False
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):

        log_msg = "Successfully parsed " + str(len(PCGUsers)) + " PCG users"
        logging.info(log_msg)
        print(f"{log_msg}\n")

    if ad_capture_success:
        for x in ppsk_users:
            user_group_id = x['user_group_id']
            email = x['email_address']
            xiq_id = x['id']
            # check if any xiq user is not included in active ad users
            if not any(d['email'] == email for d in ad_users.values()):
                if PCG_Enable == True and str(user_group_id) in PCG_Maping:
                    if pcg_capture_success == False:
                        log_msg = f"Due to PCG read failure, user {email} cannot be deleted"
                        logging.error(log_msg)
                        print(log_msg)
                        ppsk_del_error+=1
                        pcg_del_error+=1
                        continue
                # not having ppsk will break later line - if not any(d['name'] == name for d in ppsk_users):
                    # If PCG is Enabled, Users need to be deleted from PCG group before they can be deleted from User Group
                    if any(d['email'] == email for d in PCGUsers):
                        # Find specific PCG user and get the user id
                        PCGUser = (list(filter(lambda PCGUser: PCGUser['email'] == email, PCGUsers)))[0]
                        pcg_id = PCGUser['id']
                        for PCG_Map in PCG_Maping.values():
                            if PCG_Map['UserGroupName'] == PCGUser['user_group_name']:
                                policy_id = PCG_Map['policy_id']
                                policy_name = PCG_Map['policy_name']
                        result = ''
                        try:
                            result = deletePCGUsers(policy_id, pcg_id)
                        except TypeError as e:
                            logmsg = f"Failed to delete user {email} from PCG group {policy_name} with error {e}"
                            logging.error(logmsg)
                            print(logmsg)
                            ppsk_del_error+=1
                            pcg_del_error+=1
                            continue
                        except:
                            log_msg = f"Unknown Error: Failed to delete user {email} from pcg group {policy_name}"
                            logging.error(log_msg)
                            print(log_msg)
                            ppsk_del_error+=1
                            pcg_del_error+=1
                            continue
                        if result == 'Success':
                            log_msg = f"User {email} - {pcg_id} was successfully deleted from pcg group {policy_name}."
                            logging.info(log_msg)
                            print(log_msg)
                        else:
                            log_msg = f"User {email} - {pcg_id} was not successfully deleted from pcg group {policy_name}. User cannot be deleted from the PPSK Group."
                            logging.info(log_msg)
                            print(log_msg)
                            ppsk_del_error+=1
                            pcg_del_error+=1 
                            continue
                result = ''
                try:
                    result, userid = deleteUser(xiq_id)
                except TypeError as e:
                    logmsg = f"Failed to delete user {email}  with error {e}"
                    logging.error(logmsg)
                    print(logmsg)
                    ppsk_del_error+=1
                    continue
                except:
                    log_msg = f"Unknown Error: Failed to delete user {email} "
                    logging.error(log_msg)
                    print(log_msg)
                    ppsk_del_error+=1
                    continue
                if result == 'Success':
                    log_msg = f"User {email} - {userid} was successfully deleted."
                    logging.info(log_msg)
                    print(log_msg)
                else:
                    log_msg = f"User {email} - {userid} did not successfully delete from the PPSK Group."
                    logging.info(log_msg)
                    print(log_msg)
                    ppsk_del_error+=1

        if ppsk_create_error:
            log_msg = f"There were {ppsk_create_error} errors creating PPSK users on this run."
            logging.info(log_msg)
            print(log_msg)
        if pcg_create_error:
            log_msg = f"There were {pcg_create_error} errors creating PCG users on this run."
            logging.info(log_msg)
            print(log_msg)
        if ppsk_del_error:
            log_msg = f"There were {ppsk_del_error} errors deleting PPSK users on this run."
            logging.info(log_msg)
            print(log_msg)
        if pcg_del_error:
            log_msg = f"There were {pcg_del_error} errors deleting PCG users on this run."
            logging.info(log_msg)
            print(log_msg)

    else:
        log_msg = "No users will be deleted from XIQ because of the error(s) in reading azure ad users"
        logging.warning(log_msg)
        print(log_msg)


if __name__ == '__main__':
	main()
