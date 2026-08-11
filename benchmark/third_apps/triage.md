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
| descope/python-sdk | R03 | CRITICAL | descope\jwt_common.py:78 | `return jwt.decode(token, options={"verify_signature": False, "verify_a` |  |
| descope/python-sdk | R08 | MEDIUM | descope\_auth_base.py:337 | `unverified_claims = jwt.decode(` |  |
| descope/python-sdk | R09 | MEDIUM | descope\_auth_base.py:337 | `unverified_claims = jwt.decode(` |  |
| descope/python-sdk | R09 | MEDIUM | descope\_auth_base.py:358 | `claims = jwt.decode(` |  |
| zaka265-star/MyTaskly-mcp | R09 | MEDIUM | src\auth.py:67 | `payload = jwt.decode(` |  |
| zaka265-star/MyTaskly-mcp | R05 | HIGH | src\client.py:47 | `token = jwt.encode(payload, secret_key, algorithm="HS256")` |  |
| hkcoder18/2026-May-01 | R03 | CRITICAL | myenv\Lib\site-packages\redis\auth\token.py:89 | `self._decoded = jwt.decode(` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\middleware\token_usage_middleware.py:209 | `unverified = _jwt.decode(raw_token, options={"verify_signature": False` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\routers\auth.py:238 | `payload = jwt.decode(access_token, options={"verify_signature": False}` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\routers\auth.py:321 | `payload = jwt.decode(token, secret_key, algorithms=[settings.jwt_algor` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\routers\email_auth.py:300 | `payload = jwt.decode(access_token, options={"verify_signature": False}` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\routers\sso.py:438 | `payload = jwt.decode(access_token, options={"verify_signature": False}` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\services\oauth_manager.py:1924 | `claims = pyjwt.decode(` |  |
| IBM/mcp-context-forge | R11 | CRITICAL | mcpgateway\services\oauth_manager.py:1924 | `claims = pyjwt.decode(` |  |
| IBM/mcp-context-forge | R13 | CRITICAL | mcpgateway\services\oauth_manager.py:1924 | `claims = pyjwt.decode(` |  |
| IBM/mcp-context-forge | R04 | CRITICAL | mcpgateway\services\oauth_manager.py:1924 | `claims = pyjwt.decode(` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\services\token_validation_service.py:367 | `claims = jwt.decode(` |  |
| IBM/mcp-context-forge | R11 | CRITICAL | mcpgateway\services\token_validation_service.py:367 | `claims = jwt.decode(` |  |
| IBM/mcp-context-forge | R13 | CRITICAL | mcpgateway\services\token_validation_service.py:367 | `claims = jwt.decode(` |  |
| IBM/mcp-context-forge | R04 | CRITICAL | mcpgateway\services\token_validation_service.py:367 | `claims = jwt.decode(` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\transports\streamablehttp_transport.py:5394 | `unverified = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\transports\streamablehttp_transport.py:5464 | `unverified = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\utils\create_jwt_token.py:277 | `return jwt.decode(` |  |
| IBM/mcp-context-forge | R01 | CRITICAL | mcpgateway\utils\verify_credentials.py:324 | `payload = jwt.decode(token, **decode_kwargs)` |  |
| IBM/mcp-context-forge | R08 | MEDIUM | mcpgateway\utils\verify_credentials.py:324 | `payload = jwt.decode(token, **decode_kwargs)` |  |
| IBM/mcp-context-forge | R09 | MEDIUM | mcpgateway\utils\verify_credentials.py:324 | `payload = jwt.decode(token, **decode_kwargs)` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\utils\verify_credentials.py:680 | `unverified = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\utils\verify_credentials.py:1973 | `unverified = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | mcpgateway\utils\verify_credentials.py:2087 | `unverified = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R03 | CRITICAL | plugins\jwt_claims_extraction\jwt_claims_extraction.py:112 | `claims = jwt.decode(token, options={"verify_signature": False})` |  |
| IBM/mcp-context-forge | R05 | HIGH | scripts\demo_a2a_agent_auth.py:545 | `return jwt.encode(payload, JWT_SECRET, algorithm="HS256")` |  |
| wuhonglei/chat-agent | R08 | MEDIUM | backend\app\core\jwt.py:101 | `payload = jwt.decode(` |  |
| wuhonglei/chat-agent | R09 | MEDIUM | backend\app\core\jwt.py:101 | `payload = jwt.decode(` |  |
| wuhonglei/chat-agent | R03 | CRITICAL | backend\app\core\jwt.py:108 | `return jwt.decode(token, options={"verify_signature": False})` |  |
| usestapel/stapel-auth | R03 | CRITICAL | sso_service.py:349 | `info = _jwt.decode(tokens['id_token'], options={'verify_signature': Fa` |  |
| usestapel/stapel-core | R01 | CRITICAL | core\jwt_handler.py:213 | `payload = jwt.decode(` |  |
| usestapel/stapel-core | R08 | MEDIUM | core\jwt_handler.py:213 | `payload = jwt.decode(` |  |
| usestapel/stapel-core | R09 | MEDIUM | core\jwt_handler.py:213 | `payload = jwt.decode(` |  |
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
| mano8/fa-auth-m8 | R09 | MEDIUM | auth_user_service\services\service_token.py:94 | `payload = jwt.decode(` |  |
| laisfgzz/validador_JWT_local | R03 | CRITICAL | validator_jwt.py:12 | `payload = jwt.decode(token, options={"verify_signature": False})` |  |
| mano8/security-tests-m8 | R05 | HIGH | security_tests_m8\suites\algorithms.py:434 | `return jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")` |  |
| mano8/security-tests-m8 | R05 | HIGH | security_tests_m8\suites\algorithms.py:474 | `token = jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")` |  |
| mano8/security-tests-m8 | R05 | HIGH | security_tests_m8\suites\algorithms.py:510 | `token = jwt.encode(payload, _WRONG_SECRET, algorithm="HS256")` |  |
| mano8/security-tests-m8 | R03 | CRITICAL | security_tests_m8\suites\algorithms.py:562 | `payload = jwt.decode(sess["token"], options={"verify_signature": False` |  |
| mano8/security-tests-m8 | R03 | CRITICAL | security_tests_m8\suites\algorithms.py:572 | `p1 = jwt.decode(t1, options={"verify_signature": False})` |  |
| mano8/security-tests-m8 | R03 | CRITICAL | security_tests_m8\suites\algorithms.py:573 | `p2 = jwt.decode(t2, options={"verify_signature": False})` |  |
| mano8/security-tests-m8 | R05 | HIGH | security_tests_m8\suites\token_modes.py:306 | `token = jwt.encode(payload, "wrong-key-deliberately", algorithm="HS256` |  |
| scifeks/voorhees | R05 | HIGH | voorhees.py:18 | `token = jwt.encode(body, key="", algorithm="none", headers=header)` |  |
| scifeks/voorhees | R03 | CRITICAL | voorhees.py:99 | `body = jwt.decode(token, options={"verify_signature": False}, algorith` |  |
