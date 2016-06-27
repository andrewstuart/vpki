package vtls

import "testing"

func TestInterface(t *testing.T) {
	var cli interface{}
	cli = &Client{}
	if _, ok := cli.(Certifier); !ok {
		t.Fatalf("Client does not satisfy Certifier interface")
	}
}
