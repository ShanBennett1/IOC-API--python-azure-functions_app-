import logging, json, ipaddress, os, zmq
# import azure.functions as func
from azure.storage.blob import BlobServiceClient
from fastapi import FastAPI, Request, status, HTTPException
#Set env variables
connect_str = os.environ.get('BlobStorageConnString')
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_name = os.environ.get('BlobContainerName')
blackBlobFileName = os.environ.get('BlackListBlobFileName')
whiteBlobFileName = os.environ.get('WhiteListBlobFileName')
AuthKey = os.environ.get('AuthKey')

black_blob_client = blob_service_client.get_blob_client(container=container_name, blob=blackBlobFileName)
white_blob_client = blob_service_client.get_blob_client(container=container_name, blob=whiteBlobFileName)

#For getting blob data
container_client = blob_service_client.get_container_client(container_name)

app = FastAPI()
socket = zmq.Context().socket(zmq.PUB)
socket.bind("tcp://*:443")
def auth(req):
    try:
        if req.headers['Auth'] == AuthKey:
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorised"
        ) 
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorised"
        ) 

def ipval(ip):
    try:
        ipaddress.ip_address(ip)
        return
    except ValueError:
        # return func.HttpResponse(json.dumps({"message": "Invalid ip address"}), status_code=400)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
        detail="Invalid IP address")

@app.post("/api/add_blacklist")
def addblacklist(req: Request, ip: str = ''):
    #Authenticate the request
    auth(req)

    logging.info('Python HTTP trigger function processed a request.')
    #Get the blob content in json format 
    testing_BL_IPs = json.loads(container_client.download_blob(blackBlobFileName).readall())

    #Validate recived IP address
    ipval(ip)

    #append recived ip to dict
    testing_BL_IPs["ipList"].append(ip)
    #uploading to blob
    black_blob_client.upload_blob(json.dumps(testing_BL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    socket.send_string("list update")
    return testing_BL_IPs

@app.post("/api/add_whitelist")
def addwhitelist(req: Request, ip: str = ''):
    #Authenticate the request
    auth(req)

    logging.info('Python HTTP trigger function processed a request.')
    #Get the blob content in json format     
    testing_WL_IPs = json.loads(container_client.download_blob(whiteBlobFileName).readall())

    #Validate IP address
    ipval(ip)
 
    #append recived ip to dict
    testing_WL_IPs["ipList"].append(ip)
    #uploading to blob
    white_blob_client.upload_blob(json.dumps(testing_WL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    socket.send_string("list update")
    return testing_WL_IPs

@app.delete("/api/del_blacklist")
def delblacklist(req: Request, ip: str = ''):
    #Authenticate the request
    auth(req)

    logging.info('Python HTTP trigger function processed a request.')
    testing_BL_IPs = json.loads(container_client.download_blob(blackBlobFileName).readall())

    #Validate IP Address
    ipval(ip)

    #Check if IP adress exists
    if ip not in testing_BL_IPs["ipList"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP does not exist")

    for blip in testing_BL_IPs["ipList"]:
        if blip == ip:
           testing_BL_IPs["ipList"].remove(ip)

    #upload to blob storage
    black_blob_client.upload_blob(json.dumps(testing_BL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    socket.send_string("list update")
    return testing_BL_IPs

@app.delete("/api/del_whitelist")
def delwhitelist(req: Request, ip: str = ''):
    #Authenticate the request
    auth(req)

    logging.info('Python HTTP trigger function processed a request.')
    testing_WL_IPs = json.loads(container_client.download_blob(whiteBlobFileName).readall())

    #Validate IP Address
    ipval(ip)
    
    #Check is IP address exists
    if ip not in testing_WL_IPs["ipList"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP does not exist")

    for wlip in testing_WL_IPs["ipList"]:
        if wlip == ip:
           testing_WL_IPs["ipList"].remove(ip)

    white_blob_client.upload_blob(json.dumps(testing_WL_IPs, indent=4, separators=(',',': ')), overwrite=True)
    socket.send_string("list update")
    return testing_WL_IPs

@app.get("/api/get_blacklist")
def getblacklist(req: Request):
    #Authenticate the request
    auth(req)
   
    logging.info('Python HTTP trigger function processed a request.')
    #Get data from blob
    try:
        testing_BL_IPs = json.loads(container_client.download_blob(blackBlobFileName).readall())
    except:
        #blob does not exist
        return {"Message":"The IP blacklist is empty."}

    #Check is recived data is empty
    if not testing_BL_IPs["ipList"]:
        return {"Message": "The IP blacklist is empty."}

    return testing_BL_IPs

@app.get("/api/get_whitelist")
def getwhitelist(req: Request):
    #Authenticate the request
    auth(req)

    #Get data from blob
    try:
        testing_WL_IPs = json.loads(container_client.download_blob(whiteBlobFileName).readall())
    except:
        #blob does not exist
        return {"Message":"The IP whitelist is empty."}

    if not testing_WL_IPs["ipList"]:
        return {"Message": "The IP whitelist is empty."}
    
    logging.info('function returning result, 200')
    return testing_WL_IPs




# # For debugging only
# import uvicorn
# if __name__ == "__main__":
#     uvicorn.run(app,  port="8000")