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
	balances, err := client.Balance()
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	log.Print(balances["btc"].Value)
	log.Print(balances["eth"].Value)
}
