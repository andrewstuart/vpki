package vtls

import "fmt"

type VaultError struct {
	Client Client
	Orig   error
}

func (ve *VaultError) Error() string {
	return fmt.Sprintf("%s returned an error: %v", ve.Client.Addr, ve.Orig)
}
