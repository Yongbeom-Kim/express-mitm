package proxyserver

type UnexpectedHttpMethodErr struct {
	expectedMethod string
	gotMethod      string
}

func (e UnexpectedHttpMethodErr) Error() string {
	return "Unexpected HTTP method: expected " + e.expectedMethod + ", got " + e.gotMethod
}

func NewUnexpectedHttpMethodErr(expectedMethod string, gotMethod string) UnexpectedHttpMethodErr {
	return UnexpectedHttpMethodErr{expectedMethod: expectedMethod, gotMethod: gotMethod}
}
