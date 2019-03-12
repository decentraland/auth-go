# auth-go
Provides Request authentication for Decentraland services

## Credentials generation

Currently there are two types of credentials.  

### Third Party credentials

This type of credential require the intervention of a third party (authentication server) in order to authenticate the user against a service provider

```go
 timeToLive := 10 // In seconds
 credential, _ := ephemeral.GenerateSimpleCredential(timeToLive)
```  

#### Request credentials generation

##### HTTP Requests

```go
req, _ := http.NewRequest("POST", "https://yourserver.org/api/resource", strings.NewReader("{\"param\":\"data\"}"))
accessToken := "..." // Access Token given by the third party. To generate one you will need to send the ecdsa public key generated as part of the credential generation process
credential.AddRequestHeaders(req, accessToken)
```

##### Non HTTP Requests

For WebRTC or non HTTP requests you should be able to obtain all the credentials for the message you want to send
```go
msg := []byte("Your Message")
msgHash, err := utils.GenerateMessageHash(msg, now)
accessToken := "..." // Access Token given by the third party. To generate one you will need to send the ecdsa public key generated as part of the credential generation process
credential.MakeCredentials(msgHash, accessToken, now)
```

##### Generated Credentials

| Header  | Meaning | 
| ------------- | ------------- |
| x-signature | This is the signed request information (http method + url + body + timestamp) with the generated ephemeral key. This is vital to prevent replay attacks. | 
| x-timestamp | Request timestamp, in Unix time. | 
| x-auth-type | Indicates the type of credential, in this case “third-party” | 
| x-identity | The users ephemeral public key used in the access token creation and the user ID | 
| x-access-token  | Access token. Contains the public ephemeral key and it  is signed by the granting authority with its own private key. | 


### Self granted credentials

A user with an Ethereum account can generate a set of keys linked to the original account.

```go
nodeAddress := "http://127.0.0.1:8545"
accountPass := ""

c, _ := ethereum.NewEthClient(nodeAddress)
acc, _ := c.GetDefaultAccount()

accInfo := &ephemeral.EthAccountInfo{Account: acc, Passphrase: accountPass}

timeToLive := 10 // In seconds

credential, _ := ephemeral.GenerateEthBasedCredential(accInfo, c, timeToLive)
```  

#### Request credentials generation

Once you have your credentials you should be able to add the required headers to the request sent to the server who need to authenticate the user

##### HTTP Requests
```go
req, _ := http.NewRequest("POST", "https://yourserver.org/api/resource", strings.NewReader("{\"param\":\"data\"}"))
credential.AddRequestHeaders(req)
```

##### Non HTTP Requests
```go
msg := []byte("Your Message")
msgHash, err := utils.GenerateMessageHash(msg, now)
credential.MakeCredentials(msgHash, now)
```

##### Generated credentials

| Header  | Meaning | 
| ------------- | ------------- |
| x-signature | This is the signed request information (http method + url + body + timestamp) with the generated ephemeral key. This is vital to prevent replay attacks. | 
| x-timestamp | Request timestamp, in Unix time. | 
| x-auth-type | Indicates the type of credential, in this case “self-granted” | 
| x-identity | Includes information about the EHT address that generated the request and the generated ephemeral public key. | 
| x-certificate | Message that links the ephemeral key with the original ETH account. | 
| x-certificate-signature | Signature of the "x-certificate" header using the ETH key | 

## Request validation

The service providers will need to authenticate the users based on the information present in the request headers.

### Authentication Strategies

We define three basic Authentication strategies

#### Third party strategy

The service provider will need to know the entity who signs the access token, otherwise, the request will be rejected.

##### HTTP Requests
```go
reqTTL := 30 // Request time to live in seconds
trustedKey := keys.PemDecodePublicKey(pemEncodedPublicKeyString)
authnStrategy := &authentication.ThirdPartyStrategy{RequestLifeSpan: reqTTL, TrustedKey: trustedKey)}
authzStrategy := &authorization.AllowAllStrategy{}
authHandler := auth.NewAuthProvider(authnStrategy, authzStrategy)

req, _ := auth.MakeFromHttpRequest(httpRequest)
ok, err := authHandler.ApproveRequest(req)
```

##### Non HTTP Requests
```go
req, _ := auth.AuthRequest{Credentials: msgCredentials, Content: msg}
ok, err := authHandler.ApproveRequest(req)
```

#### Self Granted strategy

```go
reqTTL := 30 // Request time to live in seconds
authnStrategy := &authentication.SelfGrantedStrategy{RequestLifeSpan: reqTTL}
authzStrategy := &authorization.AllowAllStrategy{}
authHandler := auth.NewAuthProvider(authnStrategy, authzStrategy)

req, _ := auth.MakeFromHttpRequest(httpRequest)
ok, err := authHandler.ApproveRequest(req)
```

##### Non HTTP Requests
```go
req, _ := auth.AuthRequest{Credentials: msgCredentials, Content: msg}
ok, err := authHandler.ApproveRequest(req)
```

#### Allow All

```go
authnStrategy :=  &authentication.AllowAllStrategy{}
authzStrategy := &authorization.AllowAllStrategy{}
authHandler := auth.NewAuthProvider(authnStrategy, authzStrategy)

req, _ := http.TransformHttpRequest(httpRequest)
ok, err := authHandler.ApproveRequest(req)
```

## Copyright info

This repository is protected with a standard Apache 2 licence. See the terms and conditions in the [LICENSE](https://github.com/decentraland/auth-go/blob/master/LICENSE) file.

