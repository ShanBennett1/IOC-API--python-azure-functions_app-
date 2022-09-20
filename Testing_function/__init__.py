import logging
import json
import azure.functions as func
import os

logging.info('function started and getting env variable (AuthKey)')
AuthKey = os.environ.get('AuthKey')

logging.info('function entering main')
def main(req: func.HttpRequest) -> func.HttpResponse:
    #Authenticate the request
    logging.info('function getting auth')
    authReq = req.headers.get('Auth')
    logging.info('function function recived auth')
    logging.info('function checking auth')
    if authReq != AuthKey:
        logging.info('function auth isnt valid, returning 401')
        return func.HttpResponse(json.dumps({"Message": "Unauthorised Access"}), headers={"Content-Type": "application/json"}, status_code=401)

    logging.info('function returning 200')
    return func.HttpResponse(json.dumps({"Message": "Hello world"}), headers={"Content-Type": "application/json"}, status_code=200)