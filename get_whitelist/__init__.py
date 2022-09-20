import logging
import json
import azure.functions as func
import os
from azure.storage.blob import BlobServiceClient

logging.info('function started and getting env variables')
connect_str = os.environ.get('BlobStorageConnString')
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_name = os.environ.get('BlobContainerName')
blobFileName = os.environ.get('WhiteListBlobFileName')
blob_client = blob_service_client.get_blob_client(container=container_name, blob=blobFileName)
AuthKey = os.environ.get('AuthKey')
#For getting blob data
container_client = blob_service_client.get_container_client(container_name)

logging.info('Starting main')
def main(req: func.HttpRequest) -> func.HttpResponse:
    #Authenticate the request
    logging.info('function getting auth')
    authReq = req.headers.get('Auth')
    if authReq != AuthKey:
        logging.info('function auth key not valid, returning 401')
        return func.HttpResponse(json.dumps({"Message": "Unauthorised Access"}), status_code=401)

    logging.info('Python HTTP trigger function processed a request. Getting blob coontent')
    testing_WL_IPs = json.loads(container_client.download_blob(blobFileName).readall())
    logging.info('function checking if blob is empty')
    if not testing_WL_IPs["ipList"]:
        logging.info('returning error message for empty blob')
        return func.HttpResponse(json.dumps({"Message": "The IP whitelist is empty."}), headers={"Content-Type": "application/json"}, status_code=200)
    
    logging.info('function returning result, 200')
    return func.HttpResponse(json.dumps(testing_WL_IPs), headers={"Content-Type": "application/json"}, status_code=200)