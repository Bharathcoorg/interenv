# InterEnv Go SDK

Hardware-Enclave Protected Secrets for Go Applications & Microservices. Built by **Interlayer**.

## Installation

```bash
go get github.com/Bharathcoorg/interenv/go/interenv
```

Ensure the native `interenv` CLI is installed (`cargo install interenv` or `npm install -g interenv`).

## Quickstart

```go
package main

import (
	"fmt"
	"os"

	"github.com/Bharathcoorg/interenv/go/interenv"
)

func main() {
	// In-memory loading into os.Environ without writing plaintext files to disk
	if err := interenv.Load(); err != nil {
		panic(err)
	}

	apiKey := os.Getenv("STRIPE_SECRET_KEY")
	fmt.Printf("Loaded secret safely in memory: %s\n", apiKey)
}
```

## Programmatic API

```go
// Fetch all secrets as a map
secrets, err := interenv.All()

// Retrieve single secret
val := interenv.Get("DATABASE_URL")
```
