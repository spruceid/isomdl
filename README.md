# isomdl

ISO mDL implementation in Rust

## Microservice

Can be run remote or locally:
- Remote:

```
https://michael-test.spruceid.xyz
```

- Local:

```
http://127.0.0.1:9999
```


### GET `/eligibility`

```bash
curl https://michael-test.spruceid.xyz/eligibility

eligible: 0 checks performed.
```

### GET `/generate_qr_code`

```bash
curl \
  -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "issuer=https://op.dmv.ca.gov" \
  --data-urlencode "credential_type=https://dmv.ca.gov/mdl" \
  --data-urlencode "pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA" \
  --data-urlencode "user_pin=true" \
  https://michael-test.spruceid.xyz/generate_qr_code

"customscheme://example_authority/?issuer=https%3A%2F%2Fop.dmv.ca.gov&credential_type=https%3A%2F%2Fdmv.ca.gov%2Fmdl&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin_required=false"
```

### POST `/token`

```bash
curl \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  --data-urlencode "client_id=NzbLsXh8" \
  --data-urlencode "pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA" \
  --data-urlencode "user_pin=493536" \
  https://michael-test.spruceid.xyz/token

{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ","token_type":"bearer","expires_in":86400,"c_nonce":"tZignsnFbp","c_nonce_expires_in":86400}
```

#### Trigger Token Error

Note: currenly only triggered by an empty string `user_pin`.

```bash
curl \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  --data-urlencode "client_id=NzbLsXh8" \
  --data-urlencode "pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA" \
  --data-urlencode "user_pin=" \
  https://michael-test.spruceid.xyz/token

{"error":"invalid_request"}
```

### POST `/credential`

```bash
curl \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "type=https://dmv.ca.gov/mdl" \
  --data-urlencode "format=jwt_vc" \
  --data-urlencode 'proof={"proof_type": "jwt", "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleGFtcGxlX2NsYWltIjoiZXhhbXBsZV9jbGFpbV9jb250ZW50cyJ9.1BXqgc7srYMzdAM4RfF6LnROfnRb1arfngzuM6JV9_w"}' \
  https://michael-test.spruceid.xyz/credential

{"format":"ldp_vc","credential":"AAECAwQFBgc","c_nonce":"fGFF7UkhLa","c_nonce_expires_in":86400}
```

#### Trigger Credential Error

```bash
curl \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "type=https://dmv.ca.gov/mdl" \
  --data-urlencode "format=mdoc_b64u_cbor" \
  --data-urlencode 'proof={"proof_type": "jwt", "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleGFtcGxlX2NsYWltIjoiZXhhbXBsZV9jbGFpbV9jb250ZW50cyJ9.1BXqgc7srYMzdAM4RfF6LnROfnRb1arfngzuM6JV9_w"}' \
  https://michael-test.spruceid.xyz/credential

{"error":"invalid_request"}
```

