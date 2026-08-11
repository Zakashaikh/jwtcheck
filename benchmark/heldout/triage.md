# Held-out triage worksheet

Mark each finding TP (true positive) or FP (false positive) in the last column. Held-out precision = TP / (TP + FP).

| Repo | Rule | Sev | File:Line | Snippet | TP/FP |
|------|------|-----|-----------|---------|-------|
| Werner1126/smart-learning-platform | R08 | MEDIUM | backend\app\core\security.py:40 | `return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])` |  |
| Werner1126/smart-learning-platform | R09 | MEDIUM | backend\app\core\security.py:40 | `return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])` |  |
| Aadi2104/olympiad-connect | R08 | MEDIUM | app\core\security.py:57 | `token_data = jwt.decode(` |  |
| Aadi2104/olympiad-connect | R08 | MEDIUM | app\core\security.py:93 | `token_data = jwt.decode(` |  |
| ravitejakotrike/AI-Based-Verilog-TestBench-Generator | R08 | MEDIUM | backend\app\auth.py:37 | `return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` |  |
| ravitejakotrike/AI-Based-Verilog-TestBench-Generator | R09 | MEDIUM | backend\app\auth.py:37 | `return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R08 | MEDIUM | app\core\security.py:70 | `payload = jwt.decode(token, config_value.SECRET_KEY, algorithms=[confi` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R09 | MEDIUM | app\core\security.py:70 | `payload = jwt.decode(token, config_value.SECRET_KEY, algorithms=[confi` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R08 | MEDIUM | app\schemas\auth.py:96 | `payload = jwt.decode(token, config_value.SECRET_KEY, algorithms=[confi` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R09 | MEDIUM | app\schemas\auth.py:96 | `payload = jwt.decode(token, config_value.SECRET_KEY, algorithms=[confi` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R08 | MEDIUM | app\schemas\auth.py:119 | `payload = jwt.decode(refresh_token, config_value.SECRET_KEY, algorithm` |  |
| Dhruv-gif-hub/FastAPI-auth-service | R09 | MEDIUM | app\schemas\auth.py:119 | `payload = jwt.decode(refresh_token, config_value.SECRET_KEY, algorithm` |  |
| themanoj-025/UNION-BANK- | R08 | MEDIUM | src\unionbank\entrypoints\api\common.py:108 | `payload = jwt.decode(token, _get_verifying_key(), algorithms=[JWT_ALGO` |  |
| themanoj-025/UNION-BANK- | R09 | MEDIUM | src\unionbank\entrypoints\api\common.py:108 | `payload = jwt.decode(token, _get_verifying_key(), algorithms=[JWT_ALGO` |  |
| themanoj-025/UNION-BANK- | R08 | MEDIUM | src\unionbank\entrypoints\api\common.py:199 | `payload = jwt.decode(refresh_token, _get_verifying_key(), algorithms=[` |  |
| themanoj-025/UNION-BANK- | R09 | MEDIUM | src\unionbank\entrypoints\api\common.py:199 | `payload = jwt.decode(refresh_token, _get_verifying_key(), algorithms=[` |  |
| themanoj-025/UNION-BANK- | R13 | CRITICAL | src\unionbank\entrypoints\api\main.py:1619 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R08 | MEDIUM | src\unionbank\entrypoints\api\main.py:1619 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R09 | MEDIUM | src\unionbank\entrypoints\api\main.py:1619 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R13 | CRITICAL | src\unionbank\entrypoints\api\v2.py:296 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R04 | CRITICAL | src\unionbank\entrypoints\api\v2.py:296 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R08 | MEDIUM | src\unionbank\entrypoints\api\v2.py:296 | `old_payload = jwt.decode(` |  |
| themanoj-025/UNION-BANK- | R09 | MEDIUM | src\unionbank\entrypoints\api\v2.py:296 | `old_payload = jwt.decode(` |  |
| arakium/ExpenseTrackerAPI | R08 | MEDIUM | utils\auth.py:29 | `return jwt.decode(` |  |
| arakium/ExpenseTrackerAPI | R09 | MEDIUM | utils\auth.py:29 | `return jwt.decode(` |  |
| harshadx27/Cafe-REST-API | R08 | MEDIUM | app.py:136 | `payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS2` |  |
| harshadx27/Cafe-REST-API | R09 | MEDIUM | app.py:136 | `payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS2` |  |
| jayforge-dev/flask-auth-crud | R08 | MEDIUM | utils\auth_middleware.py:29 | `payload = jwt.decode(token, SECRET, algorithms=["HS256"])` |  |
| jayforge-dev/flask-auth-crud | R09 | MEDIUM | utils\auth_middleware.py:29 | `payload = jwt.decode(token, SECRET, algorithms=["HS256"])` |  |
| IcarusSec/ICARUS-Lab | R06 | HIGH | app\app.py:742 | `return pyjwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| IcarusSec/ICARUS-Lab | R08 | MEDIUM | app\app.py:742 | `return pyjwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| IcarusSec/ICARUS-Lab | R09 | MEDIUM | app\app.py:742 | `return pyjwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| IcarusSec/ICARUS-Lab | R08 | MEDIUM | app\app.py:809 | `claims = pyjwt.decode(token, key, algorithms=["HS256"])` |  |
| IcarusSec/ICARUS-Lab | R09 | MEDIUM | app\app.py:809 | `claims = pyjwt.decode(token, key, algorithms=["HS256"])` |  |
| mzulqarnain-ceh/user-auth-api | R08 | MEDIUM | auth.py:14 | `payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])` |  |
| mzulqarnain-ceh/user-auth-api | R09 | MEDIUM | auth.py:14 | `payload=jwt.decode(token,SECRET_KEY,algorithms=["HS256"])` |  |
| Gloriazhou1127/salon-event-system | R08 | MEDIUM | server\routes\auth.py:207 | `payload = pyjwt.decode(token, SSO_SECRET, algorithms=["HS256"])` |  |
| Gloriazhou1127/salon-event-system | R09 | MEDIUM | server\routes\auth.py:207 | `payload = pyjwt.decode(token, SSO_SECRET, algorithms=["HS256"])` |  |
| arXiv/arxiv-auth | R08 | MEDIUM | arxiv-auth\src\accounts\routes\ui.py:228 | `data = jwt.decode(session_cookie, secret, algorithms=["HS256"])` |  |
| arXiv/arxiv-auth | R09 | MEDIUM | arxiv-auth\src\accounts\routes\ui.py:228 | `data = jwt.decode(session_cookie, secret, algorithms=["HS256"])` |  |
| arXiv/arxiv-auth | R07 | HIGH | arxiv-auth\src\accounts\routes\ui.py:337 | `become_jwt = jwt.encode(become_jwt_data, secret)` |  |
| arXiv/arxiv-auth | R08 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\tokens.py:46 | `data = dict(jwt.decode(token, secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R09 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\tokens.py:46 | `data = dict(jwt.decode(token, secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R08 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\sessions\store.py:219 | `jwt.decode(session_jwt, self._secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R09 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\sessions\store.py:219 | `jwt.decode(session_jwt, self._secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R08 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\sessions\store.py:226 | `data = dict(jwt.decode(cookie, secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R09 | MEDIUM | arxiv-auth\src\arxiv_auth\auth\sessions\store.py:226 | `data = dict(jwt.decode(cookie, secret, algorithms=['HS256']))` |  |
| arXiv/arxiv-auth | R08 | MEDIUM | cloud_auth\arxiv\cloud_auth\jwt.py:8 | `data = dict(jwt.decode(token, secret, algorithms=["HS256"]))` |  |
| arXiv/arxiv-auth | R09 | MEDIUM | cloud_auth\arxiv\cloud_auth\jwt.py:8 | `data = dict(jwt.decode(token, secret, algorithms=["HS256"]))` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R06 | HIGH | auth_system\app.py:73 | `payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R08 | MEDIUM | auth_system\app.py:73 | `payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R09 | MEDIUM | auth_system\app.py:73 | `payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R05 | HIGH | auth_system\app.py:155 | `token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R05 | HIGH | auth_system\auth_system.py:84 | `return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R06 | HIGH | auth_system\auth_system.py:118 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R08 | MEDIUM | auth_system\auth_system.py:118 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` |  |
| Somtochukwu-Sabastine/Secure-Authentication-System | R09 | MEDIUM | auth_system\auth_system.py:118 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R05 | HIGH | extras\jwt-encode-decode.py:11 | `encoded_jwt = jwt.encode(payload, secret, algorithm=algo)` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R07 | HIGH | extras\jwt-encode-decode.py:11 | `encoded_jwt = jwt.encode(payload, secret, algorithm=algo)` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R01 | CRITICAL | extras\jwt-encode-decode.py:19 | `decoded_jwt = jwt.decode(encoded_jwt, secret, verify=True)` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R06 | HIGH | extras\jwt-encode-decode.py:19 | `decoded_jwt = jwt.decode(encoded_jwt, secret, verify=True)` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R08 | MEDIUM | extras\jwt-encode-decode.py:19 | `decoded_jwt = jwt.decode(encoded_jwt, secret, verify=True)` |  |
| alpersonalwebsite/flask-auth0-authentication-authorization | R09 | MEDIUM | extras\jwt-encode-decode.py:19 | `decoded_jwt = jwt.decode(encoded_jwt, secret, verify=True)` |  |
