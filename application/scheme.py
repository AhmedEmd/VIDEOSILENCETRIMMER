import json
import re
from pydantic import BaseModel,  validator

class TokenRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
    

    @validator('email')
    def validate_email(cls, email: str) -> str:
        """Validate the email format."""
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.(com)$', email):
            raise ValueError('Invalid email format. Must end with .com')
        return email

    @validator('password')
    def validate_password(cls, password: str) -> str:
        """Validate the password based on complexity requirements."""
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters long")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError("Password must contain at least one special character")
        return password