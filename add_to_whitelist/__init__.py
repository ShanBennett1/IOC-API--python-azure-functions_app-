import logging
import json
import ipaddress
import azure.functions as func
import os
from azure.storage.blob import BlobServiceClient

#Set env variables for blob interaction
connect_str = os.environ.get('BlobStorageConnString')
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_name = os.environ.get('BlobContainerName')
blobFileName = os.environ.get('WhiteListBlobFileName')
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blobFileName)
AuthKey = os.environ.get('AuthKey')
#For getting blob data
container_client = blob_service_client.get_container_client(container_name)

def main(req: func.HttpRequest) -> func.HttpResponse:
    #Authenticate the request
    authReq = req.headers.get('Auth')
    if authReq != AuthKey:
        return func.HttpResponse(json.dumps({"Message": "Unauthorised Access"}), status_code=401)

    logging.info('Python HTTP trigger function processed a request.')
    receivedIP = req.params.get('IP')
    #Get the blob content in json format     
    testing_WL_IPs = json.loads(container_client.download_blob(blobFileName).readall())

    #Validate IP address
    try:
        ipaddress.ip_address(receivedIP)
    except ValueError:
        return func.HttpResponse(json.dumps({"message": "Invalid ip address"}), status_code=400)
    
    if receivedIP in testing_WL_IPs["ipList"]:
        return func.HttpResponse(json.dumps({"message": "IP address already exists"}), status_code=400)
 
    #append recived ip to dict
    testing_WL_IPs["ipList"].append(receivedIP)
    #uploading to blob
    blob_client.upload_blob(json.dumps(testing_WL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    return func.HttpResponse(json.dumps(testing_WL_IPs), headers={"Content-Type": "application/json"}, status_code=200)