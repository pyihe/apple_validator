### apple_validate

Validate Sign in With Apple(IdentityCode Or IdentityToken Or RefreshToken).

### Usage

```go
package main

import "github.com/pyihe/apple_validate"

func main() {
    var appleToken = "your token"
    var jwtToken apple_validate.JWTToken
    var err error    
    
    parser := apple_validate.NewParser()
    //here if you want to check IdentityCode or RefreshToken, then you need to give the client_id, client_secret, redirect_uri param
    // parser := apple_validate.NewParser(apple_validate.WithClientID(), apple_validate.WithClientSecret(), apple_validate.WithRedirectUri())
    
    if jwtToken, err = parser.CheckIdentityToken(appleToken); err != nil {
        handleErr(err)
        return 
    }
    if ok, err := jwtToken.IsValid(); err != nil {
        handleErr(err)
        return
    } else if !ok {
        handleErr(err)
        return
    }

    //check identityCode
    //if tokenResponse, err = parser.CheckIdentityCode(appleCode); err != nil {
    //    handleErr(err)
    //    return 
    //}   
    
    //handle(tokenResponse)
}
``` 
