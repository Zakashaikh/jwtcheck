# Held-out triage worksheet

Mark each finding TP (true positive) or FP (false positive) in the last column. Held-out precision = TP / (TP + FP).

| Repo | Rule | Sev | File:Line | Snippet | TP/FP |
|------|------|-----|-----------|---------|-------|
| OPSKP/PyJWT | R08 | MEDIUM | vc.py:63 | `decoded_payload = jwt.decode(token, public_key, algorithms=["RS256"], ` |  |
| OPSKP/PyJWT | R09 | MEDIUM | vc.py:63 | `decoded_payload = jwt.decode(token, public_key, algorithms=["RS256"], ` |  |
| OPSKP/PyJWT | R03 | CRITICAL | vc_did.py:88 | `unverified_payload = jwt.decode(token, options={"verify_signature": Fa` |  |
| OPSKP/PyJWT | R08 | MEDIUM | vc_did.py:96 | `decoded_payload = jwt.decode(token, public_key, algorithms=["EdDSA"])` |  |
| OPSKP/PyJWT | R09 | MEDIUM | vc_did.py:96 | `decoded_payload = jwt.decode(token, public_key, algorithms=["EdDSA"])` |  |
| OPSKP/PyJWT | R07 | HIGH | vc_tsl.py:60 | `status_list_jwt = jwt.encode(` |  |
| OPSKP/PyJWT | R07 | HIGH | vc_tsl.py:76 | `alice_credential_jwt = jwt.encode(` |  |
| OPSKP/PyJWT | R03 | CRITICAL | vc_tsl.py:96 | `cred_payload = jwt.decode(credential_token, options={"verify_signature` |  |
| OPSKP/PyJWT | R03 | CRITICAL | vc_tsl.py:99 | `list_payload = jwt.decode(fetched_status_list_jwt, options={"verify_si` |  |
| OPSKP/PyJWT | R07 | HIGH | vc_tsl.py:119 | `bobs_mock_credential = jwt.encode(` |  |
| alexfofanov/rbac-service | R08 | MEDIUM | authentication\jwt.py:44 | `return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])` |  |
| alexfofanov/rbac-service | R09 | MEDIUM | authentication\jwt.py:44 | `return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])` |  |
| alexfofanov/rbac-service | R08 | MEDIUM | authentication\middleware.py:40 | `payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])` |  |
| alexfofanov/rbac-service | R09 | MEDIUM | authentication\middleware.py:40 | `payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])` |  |
| alexfofanov/rbac-service | R03 | CRITICAL | authentication\utils.py:22 | `payload = jwt.decode(token, options={'verify_signature': False})` |  |
| PradeepMalineni/PYJWT | R03 | CRITICAL | security\auth.py:81 | `claims = jwt.decode(token, options={"verify_signature": False})` |  |
| PradeepMalineni/PYJWT | R03 | CRITICAL | security\auth.py:141 | `claims = jwt.decode(token, options={"verify_signature": False})` |  |
| zaka265-star/MyTaskly-mcp | R09 | MEDIUM | src\auth.py:67 | `payload = jwt.decode(` |  |
| zaka265-star/MyTaskly-mcp | R05 | HIGH | src\client.py:47 | `token = jwt.encode(payload, secret_key, algorithm="HS256")` |  |
| wuhonglei/chat-agent | R08 | MEDIUM | backend\app\core\jwt.py:101 | `payload = jwt.decode(` |  |
| wuhonglei/chat-agent | R09 | MEDIUM | backend\app\core\jwt.py:101 | `payload = jwt.decode(` |  |
| wuhonglei/chat-agent | R03 | CRITICAL | backend\app\core\jwt.py:108 | `return jwt.decode(token, options={"verify_signature": False})` |  |
| Writeup-DB/JWT-101-Lab | R05 | HIGH | chal1_none\app.py:9 | `token = jwt.encode({"user": "guest", "role": "guest"}, SECRET, algorit` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal1_none\app.py:9 | `token = jwt.encode({"user": "guest", "role": "guest"}, SECRET, algorit` |  |
| Writeup-DB/JWT-101-Lab | R03 | CRITICAL | chal1_none\app.py:20 | `decoded = jwt.decode(token, options={"verify_signature": False})` |  |
| Writeup-DB/JWT-101-Lab | R06 | HIGH | chal1_none\app.py:22 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R08 | MEDIUM | chal1_none\app.py:22 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R09 | MEDIUM | chal1_none\app.py:22 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R05 | HIGH | chal2_brute\app.py:10 | `token = jwt.encode({"user": "guest", "role": "guest"}, WEAK_SECRET, al` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal2_brute\app.py:10 | `token = jwt.encode({"user": "guest", "role": "guest"}, WEAK_SECRET, al` |  |
| Writeup-DB/JWT-101-Lab | R06 | HIGH | chal2_brute\app.py:19 | `decoded = jwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R08 | MEDIUM | chal2_brute\app.py:19 | `decoded = jwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R09 | MEDIUM | chal2_brute\app.py:19 | `decoded = jwt.decode(token, WEAK_SECRET, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R05 | HIGH | chal3_kid_injection\app.py:10 | `token = jwt.encode({"user": "guest", "role": "guest"}, "dummy_secret",` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal3_kid_injection\app.py:10 | `token = jwt.encode({"user": "guest", "role": "guest"}, "dummy_secret",` |  |
| Writeup-DB/JWT-101-Lab | R08 | MEDIUM | chal3_kid_injection\app.py:28 | `decoded = jwt.decode(token, secret, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R09 | MEDIUM | chal3_kid_injection\app.py:28 | `decoded = jwt.decode(token, secret, algorithms=["HS256"])` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal5_alg_confusion\app.py:19 | `token = jwt.encode({"user": "guest", "role": "guest"}, PRIVATE_KEY, al` |  |
| Writeup-DB/JWT-101-Lab | R03 | CRITICAL | chal5_alg_confusion\app.py:52 | `decoded = jwt.decode(token, options={"verify_signature": False})` |  |
| Writeup-DB/JWT-101-Lab | R08 | MEDIUM | chal5_alg_confusion\app.py:57 | `decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])` |  |
| Writeup-DB/JWT-101-Lab | R09 | MEDIUM | chal5_alg_confusion\app.py:57 | `decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])` |  |
| Writeup-DB/JWT-101-Lab | R05 | HIGH | chal6_jku_attack\app.py:20 | `token = jwt.encode(payload, "dummy_secret", algorithm="HS256", headers` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal6_jku_attack\app.py:20 | `token = jwt.encode(payload, "dummy_secret", algorithm="HS256", headers` |  |
| Writeup-DB/JWT-101-Lab | R08 | MEDIUM | chal6_jku_attack\app.py:46 | `decoded = jwt.decode(token, public_key, algorithms=["RS256"])` |  |
| Writeup-DB/JWT-101-Lab | R09 | MEDIUM | chal6_jku_attack\app.py:46 | `decoded = jwt.decode(token, public_key, algorithms=["RS256"])` |  |
| Writeup-DB/JWT-101-Lab | R07 | HIGH | chal6_jku_attack\solution\exploit_node6.py:31 | `token = jwt.encode(payload, private_key, algorithm="RS256", headers=he` |  |
