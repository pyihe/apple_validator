### apple_validate

Validate Sign in With Apple(IdentityCode Or IdentityToken Or RefreshToken).

### Usage

```go
package main

import "github.com/pyihe/apple_validator"

func main() {
    var appleToken = "your token"
    var jwtToken apple_validator.JWTToken
    var err error    
    
    validator := apple_validator.NewValidator()
    //here if you want to check IdentityCode or RefreshToken, then you need to give the client_id, client_secret, redirect_uri params
    // validator := apple_validator.NewValidator(apple_validate.WithClientID(), apple_validate.WithClientSecret(), apple_validate.WithRedirectUri())
    
    if jwtToken, err = validator.CheckIdentityToken(appleToken); err != nil {
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
    //if tokenResponse, err = validator.CheckIdentityCode(appleCode); err != nil {
    //    handleErr(err)
    //    return 
    //}   
    
    //handle(tokenResponse)
}
``` 
