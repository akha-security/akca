package app

type CommandInput struct {
	Action    string
	Config    []byte
	Query     string
	Params    []byte
	RequestID string
}
