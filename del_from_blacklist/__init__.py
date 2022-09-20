import logging
import json
import ipaddress
import azure.functions as func
import os
from azure.storage.blob import BlobServiceClient

#from typing import Type
connect_str = os.environ.get('BlobStorageConnString')
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_name = os.environ.get('BlobContainerName')
blobFileName = os.environ.get('BlackListBlobFileName')
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
    testing_BL_IPs = json.loads(container_client.download_blob(blobFileName).readall())

    #Validate IP Address
    try:
        ipaddress.ip_address(receivedIP)
    except ValueError:
        return func.HttpResponse(json.dumps({"message": "Invalid ip address"}), status_code=400)
    if receivedIP not in testing_BL_IPs["ipList"]:
        return func.HttpResponse(json.dumps({"message": "IP does not exists"}), status_code=400)

    #Check if IP adress exists
    for ip in testing_BL_IPs["ipList"]:
        if ip == receivedIP:
           testing_BL_IPs["ipList"].remove(receivedIP)

    #upload to blob storage
    blob_client.upload_blob(json.dumps(testing_BL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    return func.HttpResponse(json.dumps(testing_BL_IPs), status_code=200)