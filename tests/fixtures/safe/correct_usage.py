import jwt
import os
payload = {"sub": "user123", "exp": 1700000000, "iat": 1699913600, "aud": "myapp", "iss": "auth.myapp.com"}
token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")
decoded = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"], audience="myapp", issuer="auth.myapp.com")
