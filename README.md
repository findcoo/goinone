# Goinone
코인원 go언어용 API 클라이언트

## API
* Account V2
  * balance
  
    ```golang
    // token string, secret string 
    // balance BalanceResponse
      client := NewClient(token, secret)
      balance, err := client.Balance()
    ```
