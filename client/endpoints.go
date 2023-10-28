package client

import "fmt"

type Endpoint struct {
	Method string
	Uri    string
}

func (e Endpoint) Url(host string) string {
	return fmt.Sprintf("%s/%s", host, e.Uri)
}
