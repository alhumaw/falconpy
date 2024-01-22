#!/usr/bin/env python3
#Please establish an "auth.py" file in the same directory as this script with the "clientid" and "clientsec" variables defined.
#This script is intended to output a list of IOCs in each Child CID listed in the auth file along with Created and Modified On/By details. Useful for regular audits of IOCs across multiple CIDs.
#Developed by Don-Swanson-Adobe

####REPLACE THE FOLLOWING EXAMPLE VARIABLES####
outpath = "../IOC_Audits.txt" #Location of the output CSV
#Note: './' is 1 directory up from current, '../' is 2 directories up
###############################################

#Import API Harness and Auth File
from falconpy import APIHarness
from auth import *

#Establish the output file
file_object = open(outpath, 'a+')
for key, value in cids.items():
    print("\n\n\n\n*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*\n"+value+"\nCID: "+key+"\n*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*\n")
    file_object.write("\n\n\n\n*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*\n"+value+"\nCID: "+key+"\n*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*_*\n")
    #Auth
    falcon = APIHarness(client_id=clientid, client_secret=clientsec, member_cid=key)

    #Query for the list of IOCs in the CID, Pull out the IOC Value, who Created/Modified it and when, then store to the output file
    response = falcon.command("indicator_search_v1")
    if len(response["body"]["resources"]):
        mleresponse = falcon.command("indicator_get_v1", ids=response["body"]["resources"])
        for detail in mleresponse["body"]["resources"]:
            mle = (detail["value"])
            createdby = (detail["created_by"])
            createdon = (detail["created_on"])
            modifiedby = (detail["modified_by"])
            modifiedon = (detail["modified_on"])
            action = (detail["action"])
            print("\nIOC: "+mle+"\nCreator: "+createdby+"\nCreated on: "+createdon+"\nLast Modified by: "+modifiedby+"\nLast Modified on: "+modifiedon+"\n")
            file_object.write("\nMLE: "+mle+"\nCreator: "+createdby+"\nCreated on: "+createdon+"\nLast Modified by: "+modifiedby+"\nLast Modified on: "+modifiedon+"\n"+"Action: "+action+"\n")

file_object.close()
