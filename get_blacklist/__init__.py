import logging
import json
import azure.functions as func
import os
from azure.storage.blob import BlobServiceClient

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
    #Get data from blob
    testing_BL_IPs = json.loads(container_client.download_blob(blobFileName).readall())

    #Check is recived data is empty
    if not testing_BL_IPs["ipList"]:
        return func.HttpResponse(json.dumps({"Message": "The IP whitelist is empty."}), headers={"Content-Type": "application/json"}, status_code=200)

    return func.HttpResponse(json.dumps(testing_BL_IPs), headers={"Content-Type": "application/json"}, status_code=200)