# Real-world triage worksheet

Mark each finding TP (true positive) or FP (false positive) in the last column. Real-world precision = TP / (TP + FP).

| Repo | Rule | Sev | File:Line | Snippet | TP/FP |
|------|------|-----|-----------|---------|-------|
| sky22333/ansible-ui | R08 | MEDIUM | app.py:932 | `payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])` | TP |
| sky22333/ansible-ui | R09 | MEDIUM | app.py:932 | `payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])` | TP |
| opensaucerer/attribute-based-access-control | R08 | MEDIUM | rsb.py:53 | `policy = jwt.decode(text, self.pk, algorithms=self.alg)` | TP |
| opensaucerer/attribute-based-access-control | R09 | MEDIUM | rsb.py:53 | `policy = jwt.decode(text, self.pk, algorithms=self.alg)` | TP |
| NoTinyxd/Hcaptcha-Solver | R03 | CRITICAL | hsw.py:52 | `url: str = "https://newassets.hcaptcha.com" + jwt.decode(token, option` | FP |
| Central-University-IT-prod/2024-hack-msk-team24-Prod_Hackaton_Backend | R05 | HIGH | ext.py:40 | `token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)` | TP |
| Central-University-IT-prod/2024-hack-msk-team24-Prod_Hackaton_Backend | R06 | HIGH | ext.py:46 | `decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| Central-University-IT-prod/2024-hack-msk-team24-Prod_Hackaton_Backend | R08 | MEDIUM | ext.py:46 | `decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| Central-University-IT-prod/2024-hack-msk-team24-Prod_Hackaton_Backend | R09 | MEDIUM | ext.py:46 | `decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| farukseker/Smart-Home-Desktop-App | R08 | MEDIUM | jw.py:5 | `rem = jwt.decode(token, algorithms='HS256')` | TP |
| farukseker/Smart-Home-Desktop-App | R09 | MEDIUM | jw.py:5 | `rem = jwt.decode(token, algorithms='HS256')` | TP |
| Oskarovsky/OskarroApp | R01 | CRITICAL | dl.py:69 | `user = jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256` | TP |
| Oskarovsky/OskarroApp | R08 | MEDIUM | dl.py:69 | `user = jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256` | TP |
| Oskarovsky/OskarroApp | R09 | MEDIUM | dl.py:69 | `user = jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256` | TP |
| Oskarovsky/OskarroApp | R01 | CRITICAL | dl.py:103 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R08 | MEDIUM | dl.py:103 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R09 | MEDIUM | dl.py:103 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R01 | CRITICAL | dl.py:121 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R08 | MEDIUM | dl.py:121 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R09 | MEDIUM | dl.py:121 | `user=jwt.decode(token.encode(), app.jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R01 | CRITICAL | resizer.py:24 | `msg = jwt.decode(body, jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R06 | HIGH | resizer.py:24 | `msg = jwt.decode(body, jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R08 | MEDIUM | resizer.py:24 | `msg = jwt.decode(body, jwt_secret_key, algorithm='HS256')` | TP |
| Oskarovsky/OskarroApp | R09 | MEDIUM | resizer.py:24 | `msg = jwt.decode(body, jwt_secret_key, algorithm='HS256')` | TP |
| IceWizard4902/VulnJWT | R05 | HIGH | jku.py:38 | `return jwt.encode({"username": username, "admin": "false", "iat": int(` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | jku.py:38 | `return jwt.encode({"username": username, "admin": "false", "iat": int(` | TP |
| IceWizard4902/VulnJWT | R08 | MEDIUM | jku.py:45 | `data = jwt.decode(token, pub_key.key, algorithms=["RS256"])` | TP |
| IceWizard4902/VulnJWT | R09 | MEDIUM | jku.py:45 | `data = jwt.decode(token, pub_key.key, algorithms=["RS256"])` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | jwk.py:28 | `return jwt.encode({"username": username, "admin": "false", "iat": int(` | TP |
| IceWizard4902/VulnJWT | R08 | MEDIUM | jwk.py:34 | `data = jwt.decode(token, signing_key.key, algorithms=["RS256"])` | TP |
| IceWizard4902/VulnJWT | R09 | MEDIUM | jwk.py:34 | `data = jwt.decode(token, signing_key.key, algorithms=["RS256"])` | TP |
| IceWizard4902/VulnJWT | R05 | HIGH | kid.py:9 | `return jwt.encode({"username": username, "admin": "false", "iat": int(` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | kid.py:9 | `return jwt.encode({"username": username, "admin": "false", "iat": int(` | TP |
| IceWizard4902/VulnJWT | R08 | MEDIUM | kid.py:19 | `data = jwt.decode(token, key, algorithms=["HS256"])` | TP |
| IceWizard4902/VulnJWT | R09 | MEDIUM | kid.py:19 | `data = jwt.decode(token, key, algorithms=["HS256"])` | TP |
| IceWizard4902/VulnJWT | R05 | HIGH | attack_poc\jku_evil.py:42 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, PRIV_KE` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | attack_poc\jku_evil.py:42 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, PRIV_KE` | TP |
| IceWizard4902/VulnJWT | R05 | HIGH | attack_poc\kid_evil.py:42 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, PRIV_KE` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | attack_poc\kid_evil.py:42 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, PRIV_KE` | TP |
| IceWizard4902/VulnJWT | R05 | HIGH | attack_poc\kid_evil.py:47 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, "", alg` | TP |
| IceWizard4902/VulnJWT | R07 | HIGH | attack_poc\kid_evil.py:47 | `token = jwt.encode({"admin": "true", "iat": int(time.time())}, "", alg` | TP |
| tastekim/Yoryjory | R06 | HIGH | main\user.py:24 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| tastekim/Yoryjory | R08 | MEDIUM | main\user.py:24 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| tastekim/Yoryjory | R09 | MEDIUM | main\user.py:24 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| tastekim/Yoryjory | R06 | HIGH | main\user.py:35 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| tastekim/Yoryjory | R08 | MEDIUM | main\user.py:35 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| tastekim/Yoryjory | R09 | MEDIUM | main\user.py:35 | `payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:75 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:75 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R07 | HIGH | API.py:197 | `token = jwt.encode( {'id': id,'username': payload['username'], 'user_t` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:245 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:245 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:352 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:352 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:502 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:502 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:611 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:611 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:682 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:682 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:756 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:756 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:813 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:813 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R08 | MEDIUM | API.py:870 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| eduardotanqueiro/Shop-DB | R09 | MEDIUM | API.py:870 | `decode_token = jwt.decode(token,jwt_key,'HS256')` | TP |
| w-yyh/Hospital_DBMS | R03 | CRITICAL | ui.py:69 | `token_data = jwt.decode(` | TP |
| w-yyh/Hospital_DBMS | R08 | MEDIUM | app\routes\auth.py:229 | `payload = jwt.decode(` | TP |
| w-yyh/Hospital_DBMS | R09 | MEDIUM | app\routes\auth.py:229 | `payload = jwt.decode(` | TP |
| w-yyh/Hospital_DBMS | R08 | MEDIUM | app\utils\auth.py:28 | `payload = jwt.decode(` | TP |
| w-yyh/Hospital_DBMS | R09 | MEDIUM | app\utils\auth.py:28 | `payload = jwt.decode(` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | auth.py:19 | `decoded_jwt = jwt.decode(jwt_token, secret_key, algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | auth.py:19 | `decoded_jwt = jwt.decode(jwt_token, secret_key, algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:41 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:41 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:79 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:79 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:119 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:119 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:147 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:147 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:180 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:180 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:305 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:305 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:327 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:327 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:358 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:358 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:376 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:376 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R08 | MEDIUM | try.py:404 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| MartinNz0m0/finalyze_backend_old | R09 | MEDIUM | try.py:404 | `decoded_jwt = jwt.decode(jwt_token, secret_key ,algorithms=['HS256'])` | TP |
| DrunkenCloud/bba_labs | R05 | HIGH | 18.py:34 | `token = jwt.encode(payload, SECRET, algorithm="HS256")` | TP |
| DrunkenCloud/bba_labs | R06 | HIGH | 18.py:43 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| DrunkenCloud/bba_labs | R08 | MEDIUM | 18.py:43 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| DrunkenCloud/bba_labs | R09 | MEDIUM | 18.py:43 | `decoded = jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| gmoraitis/newsandbooks | R09 | MEDIUM | ms.py:47 | `decoded_token = jwt.decode(token, key=public_key, algorithms=["RS256"]` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:185 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:185 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:185 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:209 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:209 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:209 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:230 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:230 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:230 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:285 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:285 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:285 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:303 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:303 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:303 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:326 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:326 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:326 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:344 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:344 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:344 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:364 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:364 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:364 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:434 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:434 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:434 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:451 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:451 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:451 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | login.py:468 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R08 | MEDIUM | login.py:468 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R09 | MEDIUM | login.py:468 | `decoded_token = jwt.decode(access_token, 'secret', algorithms=["HS256"` | TP |
| saif958/fast-api---project | R06 | HIGH | pro.py:141 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | pro.py:141 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | pro.py:141 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | pro.py:151 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | pro.py:151 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | pro.py:151 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | pro.py:173 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | pro.py:173 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | pro.py:173 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | pro.py:183 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | pro.py:183 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | pro.py:183 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R06 | HIGH | pro.py:195 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R08 | MEDIUM | pro.py:195 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| saif958/fast-api---project | R09 | MEDIUM | pro.py:195 | `decoded_token = jwt.decode(access_token,'secret',algorithms=["HS256"])` | TP |
| DHANYASHREE-MV/Data-Security-and-Privacy | R08 | MEDIUM | 2\8.py:20 | `print("Verified user from token:", jwt.decode(tok, secret, algorithms=` | TP |
| DHANYASHREE-MV/Data-Security-and-Privacy | R09 | MEDIUM | 2\8.py:20 | `print("Verified user from token:", jwt.decode(tok, secret, algorithms=` | TP |
| HaoY-l/threat-intel-hub | R08 | MEDIUM | app.py:80 | `payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options=` | TP |
| HaoY-l/threat-intel-hub | R09 | MEDIUM | app.py:80 | `payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options=` | TP |
| Sayvai-io/yoko | R08 | MEDIUM | gui.py:40 | `payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` | TP |
| Sayvai-io/yoko | R09 | MEDIUM | gui.py:40 | `payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` | TP |
| Sanhith30/online-voting-system-cloud-Slot_A | R08 | MEDIUM | va.py:36 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| Sanhith30/online-voting-system-cloud-Slot_A | R09 | MEDIUM | va.py:36 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| rozium/rs-backend | R01 | CRITICAL | rs.py:71 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| rozium/rs-backend | R08 | MEDIUM | rs.py:71 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| rozium/rs-backend | R09 | MEDIUM | rs.py:71 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| GOFONCK/ProxyPanel | R06 | HIGH | panel_server.py:574 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R08 | MEDIUM | panel_server.py:574 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R09 | MEDIUM | panel_server.py:574 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R05 | HIGH | panel_server.py:604 | `token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')` | TP |
| GOFONCK/ProxyPanel | R06 | HIGH | sss.py:547 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R08 | MEDIUM | sss.py:547 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R09 | MEDIUM | sss.py:547 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| GOFONCK/ProxyPanel | R05 | HIGH | sss.py:575 | `token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')` | TP |
| Kipl0/recipe_catalogue | R06 | HIGH | x.py:48 | `user_jwt_result = jwt.decode(` | TP |
| Kipl0/recipe_catalogue | R08 | MEDIUM | x.py:48 | `user_jwt_result = jwt.decode(` | TP |
| Kipl0/recipe_catalogue | R09 | MEDIUM | x.py:48 | `user_jwt_result = jwt.decode(` | TP |
| tushar5526/sarthi | R08 | MEDIUM | app.py:28 | `data = jwt.decode(token, app.config["SECRET_TEXT"], algorithms=["HS256` | TP |
| tushar5526/sarthi | R09 | MEDIUM | app.py:28 | `data = jwt.decode(token, app.config["SECRET_TEXT"], algorithms=["HS256` | TP |
| backslash-security-tests/demidov-small-test | R05 | HIGH | bad.py:182 | `cookie = jwt.encode(payload, 'csrf_vulneribility', algorithm='HS256')` | TP |
| backslash-security-tests/demidov-small-test | R06 | HIGH | bad.py:195 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| backslash-security-tests/demidov-small-test | R08 | MEDIUM | bad.py:195 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| backslash-security-tests/demidov-small-test | R09 | MEDIUM | bad.py:195 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| backslash-security-tests/demidov-small-test | R06 | HIGH | bad.py:207 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| backslash-security-tests/demidov-small-test | R08 | MEDIUM | bad.py:207 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| backslash-security-tests/demidov-small-test | R09 | MEDIUM | bad.py:207 | `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'` | TP |
| emilyhorsman/socialauth | R01 | CRITICAL | app.py:25 | `res = jwt.decode(request.cookies.get('jwt'), current_app.secret_key)` | TP |
| emilyhorsman/socialauth | R08 | MEDIUM | app.py:25 | `res = jwt.decode(request.cookies.get('jwt'), current_app.secret_key)` | TP |
| emilyhorsman/socialauth | R09 | MEDIUM | app.py:25 | `res = jwt.decode(request.cookies.get('jwt'), current_app.secret_key)` | TP |
| emilyhorsman/socialauth | R07 | HIGH | app.py:51 | `token = jwt.encode(` | TP |
| emilyhorsman/socialauth | R05 | HIGH | tests.py:109 | `token = jwt.encode({ 'data': { 'type': 'foobar' } }, 'sekret').decode(` | TP |
| emilyhorsman/socialauth | R07 | HIGH | tests.py:109 | `token = jwt.encode({ 'data': { 'type': 'foobar' } }, 'sekret').decode(` | TP |
| emilyhorsman/socialauth | R05 | HIGH | tests.py:116 | `token = jwt.encode({ 'data': { 'type': 'foobar' } }, 'invalid secret')` | TP |
| emilyhorsman/socialauth | R07 | HIGH | tests.py:116 | `token = jwt.encode({ 'data': { 'type': 'foobar' } }, 'invalid secret')` | TP |
| emilyhorsman/socialauth | R05 | HIGH | tests.py:123 | `token = jwt.encode({ 'data': { 'type': 'oauth_token_secret', 'id': 'fo` | TP |
| emilyhorsman/socialauth | R07 | HIGH | tests.py:123 | `token = jwt.encode({ 'data': { 'type': 'oauth_token_secret', 'id': 'fo` | TP |
| emilyhorsman/socialauth | R05 | HIGH | tests.py:137 | `token = jwt.encode({ 'data': { 'type': 'oauth_token_secret', 'id': 'fo` | TP |
| emilyhorsman/socialauth | R07 | HIGH | tests.py:137 | `token = jwt.encode({ 'data': { 'type': 'oauth_token_secret', 'id': 'fo` | TP |
| emilyhorsman/socialauth | R01 | CRITICAL | tests.py:158 | `payload = jwt.decode(res['set_token_cookie'], 'sekret', algorithm = 'H` | TP |
| emilyhorsman/socialauth | R06 | HIGH | tests.py:158 | `payload = jwt.decode(res['set_token_cookie'], 'sekret', algorithm = 'H` | TP |
| emilyhorsman/socialauth | R08 | MEDIUM | tests.py:158 | `payload = jwt.decode(res['set_token_cookie'], 'sekret', algorithm = 'H` | TP |
| emilyhorsman/socialauth | R09 | MEDIUM | tests.py:158 | `payload = jwt.decode(res['set_token_cookie'], 'sekret', algorithm = 'H` | TP |
| emilyhorsman/socialauth | R01 | CRITICAL | socialauth\providers\twitter.py:59 | `payload = jwt.decode(self.token_cookie,` | TP |
| emilyhorsman/socialauth | R08 | MEDIUM | socialauth\providers\twitter.py:59 | `payload = jwt.decode(self.token_cookie,` | TP |
| emilyhorsman/socialauth | R09 | MEDIUM | socialauth\providers\twitter.py:59 | `payload = jwt.decode(self.token_cookie,` | TP |
| emilyhorsman/socialauth | R07 | HIGH | socialauth\providers\twitter.py:115 | `self.set_token_cookie = jwt.encode(payload,` | TP |
| Sanhith30/cloud-voting-system | R08 | MEDIUM | va.py:28 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| Sanhith30/cloud-voting-system | R09 | MEDIUM | va.py:28 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| M4th3silvafatec/Zentrix | R08 | MEDIUM | v2.py:20 | `payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| M4th3silvafatec/Zentrix | R09 | MEDIUM | v2.py:20 | `payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| Anas-jaf/zaincash_project_api | R08 | MEDIUM | asd.py:85 | `decoded = jwt.decode(token, os.environ.get("SECRET"), algorithms=["HS2` | TP |
| Anas-jaf/zaincash_project_api | R09 | MEDIUM | asd.py:85 | `decoded = jwt.decode(token, os.environ.get("SECRET"), algorithms=["HS2` | TP |
| quamejnr/Python | R03 | CRITICAL | ip.py:31 | `decoded_jwt = jwt.decode(yes, options={"verify_signature": False})` | FP |
| chanzuckerberg/elk-oidc-proxy | R01 | CRITICAL | app.py:86 | `tok = jwt.decode(res.json()["id_token"],` | TP |
| chanzuckerberg/elk-oidc-proxy | R09 | MEDIUM | app.py:86 | `tok = jwt.decode(res.json()["id_token"],` | TP |
| twaasoulElm3refa/FAQ-generating | R08 | MEDIUM | FAQ.py:231 | `jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| twaasoulElm3refa/FAQ-generating | R09 | MEDIUM | FAQ.py:231 | `jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| TalaoDAO/sandbox | R09 | MEDIUM | tsl.py:36 | `return jwt.decode(token, key=key, algorithms=None, audience=audience, ` | TP |
| TalaoDAO/sandbox | R09 | MEDIUM | tsl.py:39 | `return jwt.decode(token, algorithms=None, audience=audience, options=o` | TP |
| WaggleNet/WaggleNetCloudAPI | R08 | MEDIUM | dynamo.py:27 | `out = jwt.decode(inp, pubkey, algorithms=["RS256"],` | TP |
| WaggleNet/WaggleNetCloudAPI | R09 | MEDIUM | dynamo.py:27 | `out = jwt.decode(inp, pubkey, algorithms=["RS256"],` | TP |
| dev-sariel/Paragliding | R08 | MEDIUM | App.py:45 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| dev-sariel/Paragliding | R09 | MEDIUM | App.py:45 | `data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'` | TP |
| nguyenkims/satellizer-demo | R01 | CRITICAL | app.py:84 | `payload = jwt.decode(token, app.config['TOKEN_SECRET'])` | TP |
| nguyenkims/satellizer-demo | R08 | MEDIUM | app.py:84 | `payload = jwt.decode(token, app.config['TOKEN_SECRET'])` | TP |
| nguyenkims/satellizer-demo | R09 | MEDIUM | app.py:84 | `payload = jwt.decode(token, app.config['TOKEN_SECRET'])` | TP |
| Arun1106/mytest | R03 | CRITICAL | a.py:10 | `unverified_payload = jwt.decode(token, options={"verify_signature": Fa` | FP |
| Arun1106/mytest | R03 | CRITICAL | auth.py:32 | `unverified_payload = jwt.decode(token, options={"verify_signature": Fa` | FP |
| e4stw1nd/tempShell | R08 | MEDIUM | main.py:77 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R09 | MEDIUM | main.py:77 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R08 | MEDIUM | main.py:104 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R09 | MEDIUM | main.py:104 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R08 | MEDIUM | main.py:142 | `user = jwt.decode(cookie, app.secret, algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R09 | MEDIUM | main.py:142 | `user = jwt.decode(cookie, app.secret, algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R07 | HIGH | main.py:173 | `cookie=jwt.encode({"User":username},app.secret,algorithm="HS256")` | TP |
| e4stw1nd/tempShell | R08 | MEDIUM | mod.py:29 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| e4stw1nd/tempShell | R09 | MEDIUM | mod.py:29 | `user=jwt.decode(jwt=cookie,key=app.secret,algorithms=["HS256"])` | TP |
| Mayowasamuel51/AquaSense-Backend | R08 | MEDIUM | app\dep\security.py:46 | `payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| Mayowasamuel51/AquaSense-Backend | R09 | MEDIUM | app\dep\security.py:46 | `payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| Mayowasamuel51/AquaSense-Backend | R08 | MEDIUM | app\dep\security.py:91 | `payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| Mayowasamuel51/AquaSense-Backend | R09 | MEDIUM | app\dep\security.py:91 | `payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| Mayowasamuel51/AquaSense-Backend | R07 | HIGH | app\dep\security.py:119 | `return jwt.encode(payload, JWT_SECRET, algorithm="HS256")` | TP |
| Mayowasamuel51/AquaSense-Backend | R08 | MEDIUM | app\routers\vendor.py:111 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| Mayowasamuel51/AquaSense-Backend | R09 | MEDIUM | app\routers\vendor.py:111 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| Mayowasamuel51/AquaSense-Backend | R08 | MEDIUM | app\routers\vendor_product.py:29 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| Mayowasamuel51/AquaSense-Backend | R09 | MEDIUM | app\routers\vendor_product.py:29 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| darthchild/Blockchain-Sim-Env-with-HRB-Consensus | R08 | MEDIUM | zkp.py:27 | `decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` | TP |
| darthchild/Blockchain-Sim-Env-with-HRB-Consensus | R09 | MEDIUM | zkp.py:27 | `decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` | TP |
| IBM-Cloud/trusted-profile-enterprise-security | R03 | CRITICAL | app.py:132 | `app.logger.info("IAM token: %s",jwt.decode(authTokens["access_token"],` | FP |
| IBM-Cloud/trusted-profile-enterprise-security | R03 | CRITICAL | app.py:149 | `app.logger.info("IAM token: %s",jwt.decode(authTokens["access_token"],` | FP |
| dev-yoonik/YK-Authentication-SDK-Python | R08 | MEDIUM | app.py:37 | `session_token_decoded = jwt.decode(session_token, config['YOONIK_SESSI` | TP |
| dev-yoonik/YK-Authentication-SDK-Python | R09 | MEDIUM | app.py:37 | `session_token_decoded = jwt.decode(session_token, config['YOONIK_SESSI` | TP |
| paulafredo/decode-jwt | R03 | CRITICAL | app.py:24 | `decoded = jwt.decode(token, options={"verify_signature": False})` | FP |
| paulafredo/decode-jwt | R08 | MEDIUM | app.py:37 | `jwt.decode(token, key=SECRET_KEY, algorithms=[header.get("alg", "HS256` | TP |
| paulafredo/decode-jwt | R09 | MEDIUM | app.py:37 | `jwt.decode(token, key=SECRET_KEY, algorithms=[header.get("alg", "HS256` | TP |
| Rev0kz/Flask-API-Token | R01 | CRITICAL | app.py:48 | `data = jwt.decode(token, app.config[SECRET_KEY])` | TP |
| Rev0kz/Flask-API-Token | R08 | MEDIUM | app.py:48 | `data = jwt.decode(token, app.config[SECRET_KEY])` | TP |
| Rev0kz/Flask-API-Token | R09 | MEDIUM | app.py:48 | `data = jwt.decode(token, app.config[SECRET_KEY])` | TP |
| SwagCoder18/LynqX | R05 | HIGH | rs.py:37 | `return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)` | TP |
| SwagCoder18/LynqX | R06 | HIGH | rs.py:70 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| SwagCoder18/LynqX | R08 | MEDIUM | rs.py:70 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| SwagCoder18/LynqX | R09 | MEDIUM | rs.py:70 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| DanielArturoAlejoAlvarez/Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication | R01 | CRITICAL | app.py:159 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| DanielArturoAlejoAlvarez/Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication | R08 | MEDIUM | app.py:159 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| DanielArturoAlejoAlvarez/Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication | R09 | MEDIUM | app.py:159 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| permitio/permit-hasura-python-example | R07 | HIGH | app.py:120 | `token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')` | TP |
| permitio/permit-hasura-python-example | R08 | MEDIUM | app.py:140 | `return jwt.decode(auth_token, JWT_SECRET, algorithms=['HS256'])` | TP |
| permitio/permit-hasura-python-example | R09 | MEDIUM | app.py:140 | `return jwt.decode(auth_token, JWT_SECRET, algorithms=['HS256'])` | TP |
| david4096/flask-auth0-example | R01 | CRITICAL | app.py:122 | `payload = jwt.decode(` | TP |
| david4096/flask-auth0-example | R09 | MEDIUM | app.py:122 | `payload = jwt.decode(` | TP |
| Richard-97/Diplomovka-RPI-api | R01 | CRITICAL | a.py:151 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| Richard-97/Diplomovka-RPI-api | R08 | MEDIUM | a.py:151 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| Richard-97/Diplomovka-RPI-api | R09 | MEDIUM | a.py:151 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| Richard-97/Diplomovka-RPI-api | R01 | CRITICAL | main.py:167 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| Richard-97/Diplomovka-RPI-api | R08 | MEDIUM | main.py:167 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| Richard-97/Diplomovka-RPI-api | R09 | MEDIUM | main.py:167 | `data = jwt.decode(token, app.config['SECRET_KEY'])` | TP |
| danrneal/simple-jwt-api | R08 | MEDIUM | app.py:56 | `jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| danrneal/simple-jwt-api | R09 | MEDIUM | app.py:56 | `jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| danrneal/simple-jwt-api | R08 | MEDIUM | app.py:116 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| danrneal/simple-jwt-api | R09 | MEDIUM | app.py:116 | `data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])` | TP |
| Emotional-Infrastructure/emotional-infrastructure-ct | R06 | HIGH | app.py:9 | `decoded = jwt.decode(token, "secret", algorithms=["HS256"])` | TP |
| Emotional-Infrastructure/emotional-infrastructure-ct | R08 | MEDIUM | app.py:9 | `decoded = jwt.decode(token, "secret", algorithms=["HS256"])` | TP |
| Emotional-Infrastructure/emotional-infrastructure-ct | R09 | MEDIUM | app.py:9 | `decoded = jwt.decode(token, "secret", algorithms=["HS256"])` | TP |
| Emotional-Infrastructure/emotional-infrastructure-ct | R09 | MEDIUM | server.py:110 | `payload = jwt.decode(req.token, CTP_SECRET, algorithms=["HS256"], audi` | TP |
| 3nabla3/jwt_chal | R03 | CRITICAL | app.py:23 | `decoded = jwt.decode(` | TP |
| saadiste/api-flask | R05 | HIGH | app.py:15 | `token = jwt.encode({"user": "admin", "exp": datetime.datetime.utcnow()` | TP |
| saadiste/api-flask | R06 | HIGH | app.py:25 | `jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| saadiste/api-flask | R08 | MEDIUM | app.py:25 | `jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| saadiste/api-flask | R09 | MEDIUM | app.py:25 | `jwt.decode(token, SECRET, algorithms=["HS256"])` | TP |
| Minashin1120/blue_archive_non-official_discord | R08 | MEDIUM | bot.py:417 | `try: payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256']); us` | TP |
| Minashin1120/blue_archive_non-official_discord | R09 | MEDIUM | bot.py:417 | `try: payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256']); us` | TP |
| LuckDucapa/spidey-ff-spam | R03 | CRITICAL | app.py:311 | `decoded = jwt.decode(token, options={"verify_signature": False})` | FP |
| LuckDucapa/spidey-ff-spam | R03 | CRITICAL | bot.py:360 | `decoded = jwt.decode(token, options={"verify_signature": False})` | FP |
| Terasay/probka | R07 | HIGH | bot.py:44 | `return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)` | TP |
| Terasay/probka | R08 | MEDIUM | bot.py:51 | `payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` | TP |
| Terasay/probka | R09 | MEDIUM | bot.py:51 | `payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])` | TP |
| tniquin/APPmecanica | R03 | CRITICAL | App.py:216 | `payload = jwt.decode(token, options={"verify_signature": False})` | FP |
| bvandewe/securedapi | R09 | MEDIUM | app.py:117 | `payload = jwt.decode(jwt=token, key=settings.jwt_public_key, algorithm` | TP |
| yeonholee50/NyxHub | R07 | HIGH | app.py:70 | `token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)` | TP |
| yeonholee50/NyxHub | R08 | MEDIUM | app.py:75 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| yeonholee50/NyxHub | R09 | MEDIUM | app.py:75 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| songhahaha66/chaoxing_qq_notification | R08 | MEDIUM | api.py:83 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| songhahaha66/chaoxing_qq_notification | R09 | MEDIUM | api.py:83 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| songhahaha66/chaoxing_qq_notification | R08 | MEDIUM | api.py:102 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| songhahaha66/chaoxing_qq_notification | R09 | MEDIUM | api.py:102 | `payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` | TP |
| SMARTMarkers/practitioner-ehr-app | R03 | CRITICAL | app.py:100 | `jwtDecoded = jwt.decode(idtoken, verify=False)` | FP |
| gbmeloo/iFinance-v2 | R08 | MEDIUM | app.py:154 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R09 | MEDIUM | app.py:154 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R08 | MEDIUM | app.py:178 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R09 | MEDIUM | app.py:178 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R08 | MEDIUM | app.py:193 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R09 | MEDIUM | app.py:193 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R08 | MEDIUM | app.py:228 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R09 | MEDIUM | app.py:228 | `user_data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R08 | MEDIUM | helpers.py:27 | `data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| gbmeloo/iFinance-v2 | R09 | MEDIUM | helpers.py:27 | `data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])` | TP |
| marcusrsousa/courses-be | R08 | MEDIUM | app.py:39 | `app.config['CURRENT_USER'] = jwt.decode(token, app.config.get('SECRET_` | TP |
| marcusrsousa/courses-be | R09 | MEDIUM | app.py:39 | `app.config['CURRENT_USER'] = jwt.decode(token, app.config.get('SECRET_` | TP |
| ticketfrei/ticketfrei | R07 | HIGH | db.py:198 | `return jwt.encode({` | TP |
| ticketfrei/ticketfrei | R07 | HIGH | db.py:214 | `token = jwt.encode({` | TP |
| ticketfrei/ticketfrei | R01 | CRITICAL | db.py:221 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R08 | MEDIUM | db.py:221 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R09 | MEDIUM | db.py:221 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R01 | CRITICAL | db.py:227 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R08 | MEDIUM | db.py:227 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R09 | MEDIUM | db.py:227 | `json = jwt.decode(token, self.get_secret())` | TP |
| ticketfrei/ticketfrei | R07 | HIGH | user.py:65 | `return jwt.encode({` | TP |
| revotechUET/File-Preview | R01 | CRITICAL | app.py:49 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R08 | MEDIUM | app.py:49 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R09 | MEDIUM | app.py:49 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R01 | CRITICAL | app.py:65 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R08 | MEDIUM | app.py:65 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R09 | MEDIUM | app.py:65 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R01 | CRITICAL | app.py:89 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R08 | MEDIUM | app.py:89 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R09 | MEDIUM | app.py:89 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R01 | CRITICAL | app.py:116 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R08 | MEDIUM | app.py:116 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| revotechUET/File-Preview | R09 | MEDIUM | app.py:116 | `decoded = jwt.decode(token, os.getenv('SECRET_KEY')` | TP |
| fukumame/genelate-eternal-s3-signed-url | R08 | MEDIUM | app.py:34 | `decoded = jwt.decode(encoded, secret, algorithms=['HS256'])` | TP |
| fukumame/genelate-eternal-s3-signed-url | R09 | MEDIUM | app.py:34 | `decoded = jwt.decode(encoded, secret, algorithms=['HS256'])` | TP |
