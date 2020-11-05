package apple_validate

type Parser struct {
	clientID     string //App ID
	clientSecret string //client secret
	redirectUri  string
}

func NewParser(options ...Options) *Parser {
	p := new(Parser)
	for _, op := range options {
		op(p)
	}
	return p
}

type Options func(p *Parser)

func WithClientID(clientId string) Options {
	return func(p *Parser) {
		p.clientID = clientId
	}
}

func WithClientSecret(secret string) Options {
	return func(p *Parser) {
		p.clientSecret = secret
	}
}

func WithRedirectUri(uri string) Options {
	return func(p *Parser) {
		p.redirectUri = uri
	}
}
