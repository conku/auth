package auth

// Schema auth schema
type Schema struct {
	Provider string
	UID      string

	Name      string
	Email     string
	Moblie    string
	Password  string
	FirstName string
	LastName  string
	Location  string
	Image     string
	Phone     string
	Role      string
	URL       string

	RawInfo interface{}
}
