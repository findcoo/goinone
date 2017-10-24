package goinone

import (
	"log"
	"os"
	"testing"
)

func TestBalance(t *testing.T) {
	token := os.Getenv("COINONE_TOKEN")
	secret := os.Getenv("COINONE_SECRET")

	client := NewClient(token, secret)
	balance, err := client.Balance()
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	log.Print(balance.Btc.Avail)
	log.Print(balance.Btc.Value)
}
