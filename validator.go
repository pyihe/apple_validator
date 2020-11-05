package apple_validator

type Validator struct {
	clientID     string //App ID
	clientSecret string //client secret
	redirectUri  string
}

func NewValidator(options ...Options) *Validator {
	p := new(Validator)
	for _, op := range options {
		op(p)
	}
	return p
}

type Options func(p *Validator)

func WithClientID(clientId string) Options {
	return func(p *Validator) {
		p.clientID = clientId
	}
}

func WithClientSecret(secret string) Options {
	return func(p *Validator) {
		p.clientSecret = secret
	}
}

func WithRedirectUri(uri string) Options {
	return func(p *Validator) {
		p.redirectUri = uri
	}
}
