# Video Processing Service

## Overview
This project is a FastAPI-based web service designed to process uploaded videos by detecting and trimming silent sections. It utilizes FFmpeg for video processing and integrates with AWS services for storage and user management.

---

## Features
- User authentication (signup and login)
- Video upload and processing
- Automatic detection and removal of silent parts in videos
- Secure video storage using Amazon S3
- User data management with Amazon DynamoDB

---

## Technology Stack
- **Backend Framework:** FastAPI
- **Runtime:** Python 3.x
- **Video Processing:** FFmpeg
- **Cloud Services:** Amazon Web Services (S3, DynamoDB)
- **Authentication:** JWT (JSON Web Tokens)
- **Database:** Amazon DynamoDB (NoSQL)
- **HTTPS:** Uvicorn with SSL

---

## Key Components
1. **FastAPI Application:** Handles HTTP requests, user authentication, and video processing workflows.
2. **AWS Integration:** 
   - S3 for storing original and processed videos
   - DynamoDB for user data storage
3. **Video Processing:** 
   - Utilizes FFmpeg for detecting and trimming silent parts
   - Integrates with an external Remotion service for audio analysis
4. **Authentication:** 
   - JWT-based token system for secure user authentication
   - Bcrypt for password hashing

---

## API Endpoints
- `/`: Root endpoint (for testing)
- `/login`: User login
- `/signup`: User registration
- `/process`: Video upload and processing
- `/verify-token`: Token verification
- `/contact`: Contact form submission

---

## Setup and Deployment
1. Ensure Python 3.x and FFmpeg are installed on your system.
2. Install required Python packages:
   ```
   pip install fastapi uvicorn boto3 bcrypt pydantic requests python-multipart
   ```
3. Set up AWS credentials and configure environment variables for S3 and DynamoDB access.
4. Run the application locally:
   ```
   python your_main_file.py
   ```

---

## Security
- Password hashing with bcrypt
- JWT for secure authentication
- Presigned URLs for secure S3 access

---

## Future Enhancements
- Improved error handling and logging
- Video management
- Advanced video processing options
- Scalability improvements for handling larger volumes of requests

---
