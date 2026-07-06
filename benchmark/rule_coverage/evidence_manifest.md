# Evidence manifest — commit-pinned sources for the rule-coverage study

Every confirmed hit from `coverage_hits.json`, re-downloaded and **pinned to the
exact commit SHA** so the citation is immutable even if the upstream repo changes.
Each file was re-scanned with JWTCheck on download; all 78 re-confirmed their rule.

The raw source files are archived locally under `evidence_archive/` (gitignored to
avoid redistributing third-party code under mixed licences). The permalinks below are
the citable public evidence — each was verified to resolve (HTTP 200).

**Total: 78 files across 71 repositories.**

## R02 — 'none' algorithm accepted  (20 file(s))

- [`bumahkib7/qryon` — `crates/rules/rules/python/jwt/security/jwt-none-alg.py`](https://github.com/bumahkib7/qryon/blob/227241f2e0f8b256787d2b08b603287175d7ecda/crates/rules/rules/python/jwt/security/jwt-none-alg.py) — line 10, commit `227241f2e0`
- [`Cybercommand-inc/webapp-vuln` — `31/jwt/app.py`](https://github.com/Cybercommand-inc/webapp-vuln/blob/4010c75e2e29ffba8fd6049b06cbd29d3e56e4c8/31/jwt/app.py) — line 34, commit `4010c75e2e`
- [`dacoburn/basics-test` — `custom_rules/python/jwt/security/jwt-none-alg.py`](https://github.com/dacoburn/basics-test/blob/2f37afd4d5ab3b36482507cd0fb7d97a5e79234c/custom_rules/python/jwt/security/jwt-none-alg.py) — line 10, commit `2f37afd4d5`
- [`fredericvl/py-agua-iot` — `py_agua_iot/__init__.py`](https://github.com/fredericvl/py-agua-iot/blob/db3dd530772b68b67473432301f2b8635c13dc19/py_agua_iot/__init__.py) — line 232,266, commit `db3dd53077`
- [`hiepck/ctf` — `CHH/web/The-JWT-Algorithm/create_jwt.py`](https://github.com/hiepck/ctf/blob/b1889c5e31fadc9fc416f953bb6fbecd94608ba8/CHH/web/The-JWT-Algorithm/create_jwt.py) — line 14, commit `b1889c5e31`
- [`laloba04/CasinoCTF` — `backend/app/utils/jwt_handler.py`](https://github.com/laloba04/CasinoCTF/blob/9357040f27cebac68df56fb821d74f9339d2723c/backend/app/utils/jwt_handler.py) — line 26, commit `9357040f27`
- [`NVIDIA-NeMo/nemo-platform` — `packages/nmp_common/src/nmp/common/auth/jwt.py`](https://github.com/NVIDIA-NeMo/nemo-platform/blob/4b9b24ec29adde8c0255cd08b7132d13da993a9b/packages/nmp_common/src/nmp/common/auth/jwt.py) — line 157, commit `4b9b24ec29`
- [`OlegEV/meeting-processor` — `debug_jwt.py`](https://github.com/OlegEV/meeting-processor/blob/8c3383f7e996806311a948da814bd6ebd66935a6/debug_jwt.py) — line 53, commit `8c3383f7e9`
- [`Qualytics/qualytics-cli` — `qualytics/config.py`](https://github.com/Qualytics/qualytics-cli/blob/fdf16c17f117a8eb2001c64f63d0b2e68cbee6d2/qualytics/config.py) — line 76, commit `fdf16c17f1`
- [`Qualytics/qualytics-cli` — `qualytics/mcp/server.py`](https://github.com/Qualytics/qualytics-cli/blob/fdf16c17f117a8eb2001c64f63d0b2e68cbee6d2/qualytics/mcp/server.py) — line 47, commit `fdf16c17f1`
- [`RootCauseScan/Rules` — `python/examples/jwt-none-alg.py`](https://github.com/RootCauseScan/Rules/blob/8b559cc59eb7d2920dbc8f1cd51b7c959d1f8270/python/examples/jwt-none-alg.py) — line 10, commit `8b559cc59e`
- [`semgrep/semgrep-rules` — `python/jwt/security/jwt-none-alg.py`](https://github.com/semgrep/semgrep-rules/blob/63b847ed18cb75582f49d29f8a44a349facd7a1d/python/jwt/security/jwt-none-alg.py) — line 10, commit `63b847ed18`
- [`senrishi/DeltaForce_Sysad_Task3` — `task3b/JWT Web App/jwt_webapp.py`](https://github.com/senrishi/DeltaForce_Sysad_Task3/blob/56103a3a389fc705273e40add64c4a124e0e6915/task3b/JWT%20Web%20App/jwt_webapp.py) — line 42, commit `56103a3a38`
- [`Shreyas-135/CODEGLIA` — `semgrep-rules/python/jwt/security/jwt-none-alg.py`](https://github.com/Shreyas-135/CODEGLIA/blob/c433f69171d64eec4e7e0aa39837a5d9a3ffd564/semgrep-rules/python/jwt/security/jwt-none-alg.py) — line 10, commit `c433f69171`
- [`teoconnect/aguaiot` — `py_agua_iot/__init__.py`](https://github.com/teoconnect/aguaiot/blob/6eec1ea10a2e99cc6524fdbbd70adcb309807abc/py_agua_iot/__init__.py) — line 186,219, commit `6eec1ea10a`
- [`vincentwolsink/home_assistant_micronova_agua_iot` — `custom_components/aguaiot/aguaiot.py`](https://github.com/vincentwolsink/home_assistant_micronova_agua_iot/blob/b21aaf431a022b971ca3af2b75b8949083e18c12/custom_components/aguaiot/aguaiot.py) — line 191,233, commit `b21aaf431a`
- [`viralvaghela/hack_jwt` — `hack_jwt.py`](https://github.com/viralvaghela/hack_jwt/blob/7b6efb694f0dd4f496f6d1ae6021d3a718be564f/hack_jwt.py) — line 25, commit `7b6efb694f`
- [`Vulnetix/sast-rule-evals` — `jwt/vnx-jwt-004/jwt_none_alg.py`](https://github.com/Vulnetix/sast-rule-evals/blob/99c56b0d68ad921c9c509325367a4e77bb835aec/jwt/vnx-jwt-004/jwt_none_alg.py) — line 11, commit `99c56b0d68`
- [`Vulnetix/sast-rule-evals` — `secrets/vnx-sec-015/jwt_none.py`](https://github.com/Vulnetix/sast-rule-evals/blob/99c56b0d68ad921c9c509325367a4e77bb835aec/secrets/vnx-sec-015/jwt_none.py) — line 5, commit `99c56b0d68`
- [`willi34/vulnerable-labs` — `Token/src/app/jwt_handler.py`](https://github.com/willi34/vulnerable-labs/blob/b9042774fcd91f557d18d9eadadef4baef779898/Token/src/app/jwt_handler.py) — line 21, commit `b9042774fc`

## R04 — Algorithm confusion (HMAC+asymmetric)  (24 file(s))

- [`acisoru/ctfcup22-quals` — `tasks/web/simple/deploy/app/app.py`](https://github.com/acisoru/ctfcup22-quals/blob/80392a09e304fcd17c14dd96a9139c4c2edfbdd4/tasks/web/simple/deploy/app/app.py) — line 53, commit `80392a09e3`
- [`Bihan-Banerjee/AI-Code-Security` — `LLM Code Snippets/CoPilot/Python/Task 6/cond_b.py`](https://github.com/Bihan-Banerjee/AI-Code-Security/blob/62223a8e3b97f10ed19a0cda0c78e2ad062882f3/LLM%20Code%20Snippets/CoPilot/Python/Task%206/cond_b.py) — line 25, commit `62223a8e3b`
- [`cwi-dis/igor` — `igor/access/issuer.py`](https://github.com/cwi-dis/igor/blob/1d973731a8e9378c8609401fe9fd5be963b54233/igor/access/issuer.py) — line 63, commit `1d973731a8`
- [`cwi-dis/igor` — `igorServlet.py`](https://github.com/cwi-dis/igor/blob/1d973731a8e9378c8609401fe9fd5be963b54233/igorServlet.py) — line 338, commit `1d973731a8`
- [`dannygar/ai-registry` — `teams_bot/auth_middleware.py`](https://github.com/dannygar/ai-registry/blob/ff9515b945e9384b103bdc9770a5071617f781e6/teams_bot/auth_middleware.py) — line 56, commit `ff9515b945`
- [`dannygar/ai-registry` — `teams_bot/sso.py`](https://github.com/dannygar/ai-registry/blob/ff9515b945e9384b103bdc9770a5071617f781e6/teams_bot/sso.py) — line 111, commit `ff9515b945`
- [`data-dot-all/dataall` — `deploy/custom_resources/custom_authorizer/jwt_services.py`](https://github.com/data-dot-all/dataall/blob/8227227466f3a8a8dabb37e7b8f875d613c37978/deploy/custom_resources/custom_authorizer/jwt_services.py) — line 46, commit `8227227466`
- [`dmitrii-starikov/hackatons` — `duckerz-ctf/web/CATHAT/cathat/app.py`](https://github.com/dmitrii-starikov/hackatons/blob/1efdcde60438180adc9e5db6c2242c28a43eb636/duckerz-ctf/web/CATHAT/cathat/app.py) — line 181, commit `1efdcde604`
- [`Doogit/StackBadger` — `auth/clerk.py`](https://github.com/Doogit/StackBadger/blob/021b1f49a38c0e056e97236f4d1cf327fb124d0a/auth/clerk.py) — line 435, commit `021b1f49a3`
- [`fanout/pygripcontrol` — `src/gripcontrol.py`](https://github.com/fanout/pygripcontrol/blob/2f26c395c3475435b8872a50767adea8c8e9ced3/src/gripcontrol.py) — line 89, commit `2f26c395c3`
- [`FarhadAlimohammadi-dir/vulnrepro-benchmark` — `benchmark_release/public/case_000051/src/app/routes/auth.py`](https://github.com/FarhadAlimohammadi-dir/vulnrepro-benchmark/blob/cd685b280d6678a7503fee3c19e2ac28f7847b02/benchmark_release/public/case_000051/src/app/routes/auth.py) — line 127, commit `cd685b280d`
- [`hieudzpro2k10-svg/Pentest-API` — `vulnerable_server.py`](https://github.com/hieudzpro2k10-svg/Pentest-API/blob/9f53b315496ff370469de2348b5940b056fd92bd/vulnerable_server.py) — line 226, commit `9f53b31549`
- [`krypob/keycloak-local` — `examples/oidc-demo/app.py`](https://github.com/krypob/keycloak-local/blob/235e2a3324386e58d39c516abe17bd95b5b68da7/examples/oidc-demo/app.py) — line 250, commit `235e2a3324`
- [`LeoooDias/botchat-oss` — `backend/app/auth.py`](https://github.com/LeoooDias/botchat-oss/blob/3730d94a18af5eefb6bd38db99c0685209171d40/backend/app/auth.py) — line 686,771, commit `3730d94a18`
- [`MauriceBrg/cognito-alb-fargate-demo` — `src/webapp.py`](https://github.com/MauriceBrg/cognito-alb-fargate-demo/blob/89fcd8113880b51657dcc1dd8d5061604ce16200/src/webapp.py) — line 30, commit `89fcd81138`
- [`mikeschlottig/solar-website-builder` — `services/api/routes.py`](https://github.com/mikeschlottig/solar-website-builder/blob/aafc3e8088c01f61c1bc62dbc3627b59da6143ac/services/api/routes.py) — line 676, commit `aafc3e8088`
- [`nfdi4plants/arcmanager_backend` — `app/api/endpoints/authentication.py`](https://github.com/nfdi4plants/arcmanager_backend/blob/2dfda647f4a9429e12c026daada611b0fd989eae/app/api/endpoints/authentication.py) — line 278,379, commit `2dfda647f4`
- [`nfdi4plants/arcmanager_backend` — `app/api/endpoints/projects.py`](https://github.com/nfdi4plants/arcmanager_backend/blob/2dfda647f4a9429e12c026daada611b0fd989eae/app/api/endpoints/projects.py) — line 125, commit `2dfda647f4`
- [`pepito105/Reidar.ai` — `backend/app/api/routes/memo.py`](https://github.com/pepito105/Reidar.ai/blob/07d8ef3d1bb1e27d17e875f25db5f19576726dfe/backend/app/api/routes/memo.py) — line 27, commit `07d8ef3d1b`
- [`Rodoro/CTF` — `task/web/2022/simple/deploy/app/app.py`](https://github.com/Rodoro/CTF/blob/e5ce0f1951f817724308b9c11a704e4c09b7d913/task/web/2022/simple/deploy/app/app.py) — line 53, commit `e5ce0f1951`
- [`sajjadium/ctf-archives` — `ctfs/idekCTF/2021/web/saas/util.py`](https://github.com/sajjadium/ctf-archives/blob/cd1fee0295eea9cbc3f0d6e55edfab49b092b9d9/ctfs/idekCTF/2021/web/saas/util.py) — line 26, commit `cd1fee0295`
- [`SignalPilot-Labs/SignalPilot` — `signalpilot/gateway/gateway/auth/user.py`](https://github.com/SignalPilot-Labs/SignalPilot/blob/6b039ad5c6adfee9985a802282226e97c4e39cab/signalpilot/gateway/gateway/auth/user.py) — line 255, commit `6b039ad5c6`
- [`th30d4y/OpenLearnX` — `backend/activity_logger.py`](https://github.com/th30d4y/OpenLearnX/blob/3e387c9663c15317100b481272de0158dc4aeab2/backend/activity_logger.py) — line 25, commit `3e387c9663`
- [`valginer0/PGVectorRAGIndexer` — `license.py`](https://github.com/valginer0/PGVectorRAGIndexer/blob/88b2787310cbd9e09a7edbe4edda04f07727e600/license.py) — line 321,331,351, commit `88b2787310`

## R10 — Excessive token lifetime  (6 file(s))

- [`cyweee/haxa-sec` — `haxa-jwt.py`](https://github.com/cyweee/haxa-sec/blob/8da356790f8b0c0bdf9dd22066531fd81b9ae98a/haxa-jwt.py) — line 5, commit `8da356790f`
- [`FaultMaven/faultmaven` — `scripts/generate_oauth_keys.py`](https://github.com/FaultMaven/faultmaven/blob/5e0a0b6eb14a457880557556fd609ed7a46e8613/scripts/generate_oauth_keys.py) — line 95, commit `5e0a0b6eb1`
- [`isabellepayer5062-alt/CaseCrack_Backup2` — `_casecrack_dev/system_validation/_phase2_aud_extraction.py`](https://github.com/isabellepayer5062-alt/CaseCrack_Backup2/blob/e0c7cd92c777232c275b6c40667dd5190a607f4e/_casecrack_dev/system_validation/_phase2_aud_extraction.py) — line 404, commit `e0c7cd92c7`
- [`osirislab/CSAW-RED-2018-Quals` — `Web/Adrift/solver.py`](https://github.com/osirislab/CSAW-RED-2018-Quals/blob/5228845c1aa5d07ccb4ae2de753922649e153078/Web/Adrift/solver.py) — line 65, commit `5228845c1a`
- [`sstrntu/turfmapp-ai-agent` — `backend/app/core/jwt_auth.py`](https://github.com/sstrntu/turfmapp-ai-agent/blob/510bb9e5a2eda360d730fadf1d9a11fff0857b75/backend/app/core/jwt_auth.py) — line 125, commit `510bb9e5a2`
- [`zionsworking/jwt-differential-fuzzer` — `scripts/build_corpus.py`](https://github.com/zionsworking/jwt-differential-fuzzer/blob/c8921f0cad681a6e74766754af129907fa5f4057/scripts/build_corpus.py) — line 72,75,78,202,219,305, commit `c8921f0cad`

## R11 — Issuer verification disabled  (9 file(s))

- [`aleiepure/devtoolbox` — `src/services/jwt_decoder.py`](https://github.com/aleiepure/devtoolbox/blob/de7d6f2c0198730651660b3618ec9da4a04b49cc/src/services/jwt_decoder.py) — line 56, commit `de7d6f2c01`
- [`dakotalatommy/Aube-Coding-Framework` — `src/backend/app/auth.py`](https://github.com/dakotalatommy/Aube-Coding-Framework/blob/d82bf7e19eb6c25a8fbc565e18cce34f45fac41b/src/backend/app/auth.py) — line 77,161,243, commit `d82bf7e19e`
- [`dataloop-ai/dtlpy` — `dtlpy/entities/app.py`](https://github.com/dataloop-ai/dtlpy/blob/17e171875ddf6ab7fbfdb08d828ebcbaaa049040/dtlpy/entities/app.py) — line 168, commit `17e171875d`
- [`jexia/jexia-sdk-python` — `jexia_sdk/http.py`](https://github.com/jexia/jexia-sdk-python/blob/6e934222f06ac7600f3f86940480899f570b226f/jexia_sdk/http.py) — line 186, commit `6e934222f0`
- [`jjulien/azure-query` — `src/aq/token.py`](https://github.com/jjulien/azure-query/blob/2da8ee35a58602d70225946d915f172c4b7a452d/src/aq/token.py) — line 114, commit `2da8ee35a5`
- [`NVIDIA-NeMo/nemo-platform` — `packages/nmp_common/src/nmp/common/auth/jwt.py`](https://github.com/NVIDIA-NeMo/nemo-platform/blob/4b9b24ec29adde8c0255cd08b7132d13da993a9b/packages/nmp_common/src/nmp/common/auth/jwt.py) — line 157, commit `4b9b24ec29`
- [`OlegEV/meeting-processor` — `debug_jwt.py`](https://github.com/OlegEV/meeting-processor/blob/8c3383f7e996806311a948da814bd6ebd66935a6/debug_jwt.py) — line 53, commit `8c3383f7e9`
- [`rscarrera27/Sanic-JWT-Extended` — `sanic_jwt_extended/tokens.py`](https://github.com/rscarrera27/Sanic-JWT-Extended/blob/0eb9282a4c21f6d9a81c3d3c2a4818353b79b429/sanic_jwt_extended/tokens.py) — line 130, commit `0eb9282a4c`
- [`W1ndst0rm/Treillage` — `treillage/token_manager.py`](https://github.com/W1ndst0rm/Treillage/blob/35942e21417837f61ad9a4b0edefdcc8e9daec7b/treillage/token_manager.py) — line 101, commit `35942e2141`

## R12 — Excessive leeway  (7 file(s))

- [`Kamalesh1512/pleero` — `backend/app/utils/app_bridge_auth.py`](https://github.com/Kamalesh1512/pleero/blob/a1f582ec64266e1e31f85a492a5c41b5992d0e5a/backend/app/utils/app_bridge_auth.py) — line 51, commit `a1f582ec64`
- [`knutj42/snowrobot` — `remotecontrol/server/controlcenter/controlcenter/views/authentication.py`](https://github.com/knutj42/snowrobot/blob/212da888d07d49a225c9ea8f626e80f8b7fe2141/remotecontrol/server/controlcenter/controlcenter/views/authentication.py) — line 53, commit `212da888d0`
- [`lifcompany/Blitzwrite_Backend` — `users/views.py`](https://github.com/lifcompany/Blitzwrite_Backend/blob/9942e77e174556173d11f9efd59739718c21934b/users/views.py) — line 592, commit `9942e77e17`
- [`maxdiegoduron/Measurement-Hub` — `src/components/get_user.py`](https://github.com/maxdiegoduron/Measurement-Hub/blob/e76d17f29c9f3b5a0c35392b0ed8472762bf2ce8/src/components/get_user.py) — line 30, commit `e76d17f29c`
- [`maxdiegoduron/Measurement-Hub` — `utils/st_utils.py`](https://github.com/maxdiegoduron/Measurement-Hub/blob/e76d17f29c9f3b5a0c35392b0ed8472762bf2ce8/utils/st_utils.py) — line 855, commit `e76d17f29c`
- [`tarun-khatri/auto-twitter-replies` — `backend/clerk_auth.py`](https://github.com/tarun-khatri/auto-twitter-replies/blob/8163ae2c46387328b859df53bc12419879a2c729/backend/clerk_auth.py) — line 30, commit `8163ae2c46`
- [`tw1nflame/nwc` — `backend/app/utils/auth.py`](https://github.com/tw1nflame/nwc/blob/3b21bada89f642ec972902af39b3b7caf5f77d2b/backend/app/utils/auth.py) — line 18, commit `3b21bada89`

## R13 — Expiry verification disabled  (18 file(s))

- [`airladon/ThisIGet` — `app/app/models.py`](https://github.com/airladon/ThisIGet/blob/e54058056ed593ff1097ef4505a5ce97ea09d94b/app/app/models.py) — line 171,215, commit `e54058056e`
- [`aleiepure/devtoolbox` — `src/services/jwt_decoder.py`](https://github.com/aleiepure/devtoolbox/blob/de7d6f2c0198730651660b3618ec9da4a04b49cc/src/services/jwt_decoder.py) — line 56, commit `de7d6f2c01`
- [`anbu101/scalp-app` — `backend/app/license/license_client.py`](https://github.com/anbu101/scalp-app/blob/81e1e174e94516b729e3836f8c793714067a1c2d/backend/app/license/license_client.py) — line 195, commit `81e1e174e9`
- [`CSCfi/pebbles` — `pebbles/client.py`](https://github.com/CSCfi/pebbles/blob/3f0441858a2cbd80b859593c29068d121b929053/pebbles/client.py) — line 29, commit `3f0441858a`
- [`dakotalatommy/Aube-Coding-Framework` — `src/backend/app/auth.py`](https://github.com/dakotalatommy/Aube-Coding-Framework/blob/d82bf7e19eb6c25a8fbc565e18cce34f45fac41b/src/backend/app/auth.py) — line 77,161,243, commit `d82bf7e19e`
- [`dannygar/ai-registry` — `teams_bot/auth_middleware.py`](https://github.com/dannygar/ai-registry/blob/ff9515b945e9384b103bdc9770a5071617f781e6/teams_bot/auth_middleware.py) — line 56, commit `ff9515b945`
- [`dannygar/ai-registry` — `teams_bot/sso.py`](https://github.com/dannygar/ai-registry/blob/ff9515b945e9384b103bdc9770a5071617f781e6/teams_bot/sso.py) — line 111, commit `ff9515b945`
- [`dataloop-ai/dtlpy` — `dtlpy/entities/app.py`](https://github.com/dataloop-ai/dtlpy/blob/17e171875ddf6ab7fbfdb08d828ebcbaaa049040/dtlpy/entities/app.py) — line 168, commit `17e171875d`
- [`eastmoon1117/JKerCloudMonitor` — `auth/__init__.py`](https://github.com/eastmoon1117/JKerCloudMonitor/blob/94990407961ca4498278c50304b30162100e0389/auth/__init__.py) — line 36,74, commit `9499040796`
- [`java-crypto/cross_platform_crypto` — `JwtJwsRs256Signature/JwsRs256Signature.py`](https://github.com/java-crypto/cross_platform_crypto/blob/0c8ec72d215afdd71da7c11e9a25b917b279e877/JwtJwsRs256Signature/JwsRs256Signature.py) — line 26, commit `0c8ec72d21`
- [`jjulien/azure-query` — `src/aq/token.py`](https://github.com/jjulien/azure-query/blob/2da8ee35a58602d70225946d915f172c4b7a452d/src/aq/token.py) — line 114, commit `2da8ee35a5`
- [`Kenxu2022/MUChat` — `utils/token.py`](https://github.com/Kenxu2022/MUChat/blob/2755f55260ab6707fb878c31a8b780e824824b98/utils/token.py) — line 81, commit `2755f55260`
- [`kujirashark/user_restful_api` — `utils/auth_helper.py`](https://github.com/kujirashark/user_restful_api/blob/ac5fbd8b8e27096a90f1a8998506337fbb41324c/utils/auth_helper.py) — line 70, commit `ac5fbd8b8e`
- [`MLT-OSS/open-assistant-api` — `app/libs/util.py`](https://github.com/MLT-OSS/open-assistant-api/blob/bcdfb9bdaf9d755d126d491b82d28e6edf91d929/app/libs/util.py) — line 34, commit `bcdfb9bdaf`
- [`NousResearch/hermes-agent` — `plugins/dashboard_auth/self_hosted/__init__.py`](https://github.com/NousResearch/hermes-agent/blob/7426c09beee73bdff94d916015bac71384f6bc92/plugins/dashboard_auth/self_hosted/__init__.py) — line 640, commit `7426c09bee`
- [`phuvinh010701/mezon-sdk-python` — `mezon/session.py`](https://github.com/phuvinh010701/mezon-sdk-python/blob/4313c8cfc5bbd79f3d0e2cd92083306d39b7b028/mezon/session.py) — line 50,102,110, commit `4313c8cfc5`
- [`presidio-v/presidio-hardened-fastapi` — `attack.py`](https://github.com/presidio-v/presidio-hardened-fastapi/blob/a9284af018f7d21d68f4fdb109d99e8759b4a738/attack.py) — line 60, commit `a9284af018`
- [`valginer0/PGVectorRAGIndexer` — `license.py`](https://github.com/valginer0/PGVectorRAGIndexer/blob/88b2787310cbd9e09a7edbe4edda04f07727e600/license.py) — line 321,331,351, commit `88b2787310`

## R14 — PEM key as string literal  (3 file(s))

- [`24f2000062/jwt-verifier` — `main.py`](https://github.com/24f2000062/jwt-verifier/blob/a52f34271886dc8b7c3f1df30abdba01c7ec59c1/main.py) — line 31, commit `a52f342718`
- [`Matthew1471/Enphase-API` — `Python/src/enphase_api/cloud/authentication.py`](https://github.com/Matthew1471/Enphase-API/blob/1b434ac38e5335ca4ef2dfe268d992565653cd6f/Python/src/enphase_api/cloud/authentication.py) — line 386, commit `1b434ac38e`
- [`sajjadium/ctf-archives` — `ctfs/TBTL/2024/misc/Your_papers_please/server.py`](https://github.com/sajjadium/ctf-archives/blob/cd1fee0295eea9cbc3f0d6e55edfab49b092b9d9/ctfs/TBTL/2024/misc/Your_papers_please/server.py) — line 38, commit `cd1fee0295`

## R15 — Env secret, algorithms unpinned  (2 file(s))

- [`Bihan-Banerjee/AI-Code-Security` — `LLM Code Snippets/CoPilot/Python/Task 6/cond_b.py`](https://github.com/Bihan-Banerjee/AI-Code-Security/blob/62223a8e3b97f10ed19a0cda0c78e2ad062882f3/LLM%20Code%20Snippets/CoPilot/Python/Task%206/cond_b.py) — line 25, commit `62223a8e3b`
- [`hieudzpro2k10-svg/Pentest-API` — `vulnerable_server.py`](https://github.com/hieudzpro2k10-svg/Pentest-API/blob/9f53b315496ff370469de2348b5940b056fd92bd/vulnerable_server.py) — line 226, commit `9f53b31549`
