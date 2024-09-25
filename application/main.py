import logging
import os
import subprocess
import tempfile
from fastapi import FastAPI, File, HTTPException, Header, Request, Response, UploadFile, logger, status, Depends
from typing import Dict, Optional
import boto3
from bcrypt import checkpw, hashpw
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError
from botocore.exceptions import NoCredentialsError
import requests
from email.mime.text import MIMEText
import smtplib
from botocore.client import Config
from authentication import create_access_token, verify_token
from scheme import TokenRequest , SignupRequest


app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
UPLOAD_BUCKET = os.getenv('UPLOAD_BUCKET')
PROCESSED_BUCKET = os.getenv('PROCESSED_BUCKET')
REMOTION_SERVICE_URL = os.getenv('REMOTION_SERVICE_URL')
MYMAIL = os.getenv('MYMAIL')
MAILCODE = os.getenv('MAILCODE')
TABLENAME = os.getenv('TABLENAME')

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for error in exc.errors():
        error_msg = f"{error['loc'][-1]}: {error['msg']}"
        errors.append(error_msg)
    return JSONResponse(
        status_code=400,
        content={"detail": errors}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

dynamodb = boto3.resource(
    'dynamodb',
    region_name='us-east-2'
)

table = dynamodb.Table(TABLENAME)
s3_client = boto3.client('s3', config=Config(signature_version='s3v4', ), region_name='us-east-2')

@app.get("/")
def read_root():
    response = table.scan()
    return response['Items']

@app.get("/items")
def get_items():
    try:
        response = table.scan()
    except Exception as e:
        print(f"Error accessing DynamoDB: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to access DynamoDB")
    return response['Items']

@app.post("/login")
def login_for_access_token(response: Response, request: TokenRequest):
    username = request.username
    password = request.password
    dynamo_response = table.get_item(Key={'username': username})
    
    if 'Item' not in dynamo_response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = dynamo_response['Item']
    hashed_password = user.get('password')
    
    if not hashed_password or not checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": username})
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/signup")
async def signup(signup_request: SignupRequest):
    try:
        access_token = create_access_token(data={"sub": signup_request.username})
        
        return {"message": "Signup successful", "access_token": access_token}
    except ValidationError as e:
        error_messages = []
        for error in e.errors():
            error_messages.append(f"{error['loc'][0]}: {error['msg']}")
        return JSONResponse(
            status_code=400,
            content={"detail": error_messages}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": str(e)}
        )

@app.post("/deleteuser")
def delete_user(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header format")
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
        response = table.delete_item(
            Key={
                'username': username
            }
        )
        
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200:
            return {"message": "User deleted successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.post("/process")
async def process_video(file: UploadFile = File(...)):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file_path = os.path.join(tmpdir, file.filename)
            with open(input_file_path, "wb") as buffer:
                buffer.write(await file.read())
            
            logger.info(f"Saved uploaded file to {input_file_path}")
            
            s3_client.upload_file(input_file_path, UPLOAD_BUCKET, file.filename)
            logger.info(f"Uploaded original file to S3 bucket: {UPLOAD_BUCKET}")
            
            with open(input_file_path, 'rb') as video_file:
                files = {'video': video_file}
                response = requests.post(REMOTION_SERVICE_URL, files=files)
                response.raise_for_status()
            
            audible_parts = response.json()
            logger.info(f"Detected audible parts: {audible_parts}")

            audible_parts = [
                part for part in audible_parts
                if part.get('start') is not None and part.get('end') is not None
            ]
            logger.info(f"Filtered audible parts: {audible_parts}")

            if not audible_parts:
                processed_video_url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': UPLOAD_BUCKET, 'Key': file.filename},
                    ExpiresIn=300
                )
                logger.info(f"Generated presigned URL for original video: {processed_video_url}")
                return {"processed_video_url": processed_video_url}

            output_file_name = f"processed_{file.filename}"
            output_file_path = os.path.join(tmpdir, output_file_name)
            
            filter_complex = ''
            concat_parts = []
            
            for i, part in enumerate(audible_parts):
                filter_complex += (
                    f"[0:v]trim=start={part['start']}:end={part['end']}," 
                    f"setpts=PTS-STARTPTS[v{i}];"
                    f"[0:a]atrim=start={part['start']}:end={part['end']}," 
                    f"asetpts=PTS-STARTPTS[a{i}];"
                )
                concat_parts.append(f'[v{i}][a{i}]')

            filter_complex += ''.join(concat_parts) + f"concat=n={len(audible_parts)}:v=1:a=1[outv][outa]"
            
            ffmpeg_command = [
                'ffmpeg',
                '-i', input_file_path,
                '-filter_complex', filter_complex,
                '-map', '[outv]',
                '-map', '[outa]',
                output_file_path
            ]
            
            logger.info(f"Running FFmpeg command: {' '.join(ffmpeg_command)}")
            subprocess.run(ffmpeg_command, check=True)
            logger.info(f"Processed video saved to {output_file_path}")
            
            s3_client.upload_file(output_file_path, PROCESSED_BUCKET, output_file_name)
            logger.info(f"Uploaded processed file to S3 bucket: {PROCESSED_BUCKET}")
            
            processed_video_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': PROCESSED_BUCKET, 'Key': output_file_name},
                ExpiresIn=3600
            )

            logger.info(f"Generated presigned URL for processed video: {processed_video_url}")
            
            return {"processed_video_url": processed_video_url}
    
    except NoCredentialsError:
        logger.error("AWS credentials not found.")
        raise HTTPException(status_code=403, detail="AWS credentials not found.")
    except Exception as e:
        logger.error(f"Error processing video: {e}")
        raise HTTPException(status_code=500, detail="Error processing video.")
