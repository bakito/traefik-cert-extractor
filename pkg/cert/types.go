package cert

type Acme map[string]Resolver

type Resolver struct {
	Account      Account       `json:"Account"`
	Certificates []Certificate `json:"Certificates"`
}

type Certificate struct {
	Domain      Domain `json:"domain"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Store       string `json:"Store"`
}

type Domain struct {
	Main string `json:"main"`
}

type Account struct {
	Email        string       `json:"Email"`
	Registration Registration `json:"Registration"`
	PrivateKey   string       `json:"PrivateKey"`
	KeyType      string       `json:"KeyType"`
}

type Registration struct {
	Body Body   `json:"body"`
	URI  string `json:"uri"`
}

type Body struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
}
