package cert

// Acme file type
type Acme map[string]Resolver

// Resolver cert resolver
type Resolver struct {
	Account      Account       `json:"Account"`
	Certificates []Certificate `json:"Certificates"`
}

// Certificate a certificate
type Certificate struct {
	Domain      Domain `json:"domain"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Store       string `json:"Store"`
}

// Domain cert domain
type Domain struct {
	Main string `json:"main"`
}

// Account resolver account
type Account struct {
	Email        string       `json:"Email"`
	Registration Registration `json:"Registration"`
	PrivateKey   string       `json:"PrivateKey"`
	KeyType      string       `json:"KeyType"`
}

// Registration account registration
type Registration struct {
	Body Body   `json:"body"`
	URI  string `json:"uri"`
}

// Body registration body
type Body struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
}
