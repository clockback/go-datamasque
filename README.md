# go-datamasque

Web client written in Go for interacting with DataMasque.

## Usage

```go
client, err := datamasque.New(&datamasque.ClientConfig{
	BaseURL: "https://mydatamasqueinstance.com",
	Timeout: 30 * time.Second,
})
if err != nil {
	// Handle the error
}

ctx, cancel := context.WithTimeout(context.Background(), 60 * time.Second)
defer cancel()

session, err := client.Login(ctx, "myusername", "mypassword")
if err != nil {
	// Handle the error
}

if err != client.Logout(ctx, session); err != nil {
	// Handle the error
}
```
