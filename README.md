# auth-go
Provides Request authentication for Decentraland services

## Credentials generation

This type of credential require the intervention of a third party (authentication server) in order to authenticate the user against a service provider

```go
import "github.com/decentraland/auth-go/pkg/ephemeral"

ephKey, _  := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})
```  

#### Request credentials generation

##### HTTP Requests

```go
import (
	"github.com/decentraland/auth-go/pkg/ephemeral"
	"net/http"
	"strings"
)

req, _ := http.NewRequest("POST", "https://yourserver.org/api/resource", strings.NewReader("{\"param\":\"data\"}"))
accessToken := "..." // Access Token given by the third party. To generate one you will need to send the ecdsa public key generated as part of the credential generation process
ephKey.AddRequestHeaders(req, accessToken)
```

##### Non HTTP Requests

For WebRTC or non HTTP requests you should be able to obtain all the credentials for the message you want to send
```go
import "github.com/decentraland/auth-go/pkg/ephemeral"

ephKey, _  := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})

msg := []byte("Your Message")

accessToken := "..." // Access Token given by the third party. To generate one you will need to send the ecdsa public key generated as part of the credential generation process

ephKey.MakeCredentials(msg, accessToken)
```

##### Generated Credentials

| Header  | Meaning | 
| ------------- | ------------- |
| x-signature | This is the signed request information (http method + url + body + timestamp) with the generated ephemeral key. This is vital to prevent replay attacks. | 
| x-timestamp | Request timestamp, in Unix time. | 
| x-identity | The users ephemeral public key used in the access token creation and the user ID | 
| x-access-token  | Access token. Contains the public ephemeral key and it  is signed by the granting authority with its own private key. | 


## Request validation

The service providers will need to authenticate the users based on the information present in the request headers.

### Authentication Strategies

We define two basic Authentication strategies

#### Authentication based on a Third party

The service provider will need to know the entity who signs the access token, otherwise, the request will be rejected.

##### HTTP Requests
```go
import (
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/decentraland/auth-go/pkg/keys"
)

reqTTL := 30 // Request time to live in seconds
trustedKey := keys.PemDecodePublicKey(pemEncodedPublicKeyString)
authHandler, err := auth.NewThirdPartyAuthProvider(&auth.ThirdPartyProviderConfig{RequestLifeSpan: reqTTL, TrustedKey: trustedKey})

req, _ := auth.MakeFromHttpRequest(httpRequest)
result, err := authHandler.ApproveRequest(req)

// Get UserID
userID := result.GetUserID() // Extracted from the access token
```

##### Non HTTP Requests
```go
import (
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/decentraland/auth-go/pkg/keys"
)

reqTTL := 30 // Request time to live in seconds
trustedKey := keys.PemDecodePublicKey(pemEncodedPublicKeyString)
authHandler, err := auth.NewThirdPartyAuthProvider(&auth.ThirdPartyProviderConfig{RequestLifeSpan: reqTTL, TrustedKey: trustedKey})


msgCredentials := make(map[string]string)

msgCredentials[auth.HeaderAccessToken] = ""
//...
msgCredentials[auth.HeaderTimestamp] = "150000000"

msg := []byte("Your Message To Validate")
req := &auth.AuthRequest{Credentials: msgCredentials, Content: msg}
result, err := authHandler.ApproveRequest(req)

// Get UserID
userID := result.GetUserID() // Extracted from the access token
```

#### Allow All

```go
import (
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/decentraland/auth-go/pkg/authentication"
	"github.com/decentraland/auth-go/pkg/authorization"
	"net/http"
)

authnStrategy :=  &authentication.AllowAllStrategy{}
authzStrategy := &authorization.AllowAllStrategy{}
authHandler := auth.NewAuthProvider(authnStrategy, authzStrategy)

var httpRequest http.Response
// httpRequest = ...

req, _ := http.TransformHttpRequest(httpRequest)
ok, err := authHandler.ApproveRequest(req)
```

#### Custom Strategies

The service provide could opt to implement its own auth strategy. The only thing to do is to implement  `AuthenticationStrategy` and `AuthorizationStrategy` interfaces 

## go-ethereum

The code under the [ethereum directory](internal/ethereum) was taken from [go-ethereum](https://github.com/ethereum/go-ethereum) implementation

## Copyright info

This repository is protected with a standard Apache 2 licence. See the terms and conditions in the [LICENSE](https://github.com/decentraland/auth-go/blob/master/LICENSE) file.





