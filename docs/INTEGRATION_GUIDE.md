# InterEnv Framework Integration Guide

Seamlessly integrate zero-plaintext secret management across popular modern web frameworks and deployment environments.

---

## 1. Node.js & TypeScript Frameworks

### Next.js
In `next.config.js` or custom server:
```javascript
const { config } = require("interenv");
config();

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
};

module.exports = nextConfig;
```

### Express / Fastify
At the top of your application entrypoint (`src/index.ts`):
```typescript
import { config } from "interenv";
config(); // Must be called before accessing any process.env variables

import express from "express";
const app = express();
const port = process.env.PORT || 3000;
```

---

## 2. Python Frameworks

### FastAPI
In `app/main.py`:
```python
import interenv
interenv.load_env()

from fastapi import FastAPI
import os

app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "ok", "db_configured": bool(os.getenv("DATABASE_URL"))}
```

### Django
In `manage.py` and `wsgi.py`:
```python
#!/usr/bin/env python
import os
import sys
import interenv

def main():
    interenv.load_env()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
    # ...
```

---

## 3. Go Microservices

### Gin Web Framework
In `main.go`:
```go
package main

import (
	"os"
	"github.com/gin-gonic/gin"
	"github.com/Bharathcoorg/interenv/go/interenv"
)

func main() {
	if err := interenv.Load(); err != nil {
		panic(err)
	}

	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"api_key_set": os.Getenv("API_KEY") != "",
		})
	})
	r.Run()
}
```

---

## 4. PHP & Laravel

### Laravel Integration
In `bootstrap/app.php`:
```php
<?php

use InterEnv\InterEnv;

// Populate in-memory environment before Laravel boots
InterEnv::load();

return Illuminate\Foundation\Application::configure(basePath: dirname(__DIR__))
    // ...
```

---

## 5. Headless Container & Server Deployments

To use InterEnv inside containerized or headless Linux environments:

```dockerfile
FROM node:20-bookworm-slim AS runner
WORKDIR /app

# Install native release binary via npm or direct release download
RUN npm install -g interenv

COPY . .

# Run with in-memory injection via passphrase in CI/CD
ENV INTERENV_CI=1
ENTRYPOINT ["interenv", "run", "--", "node", "server.js"]
```

Supply the decryption passphrase via container runtime environment variables:
```bash
docker run -e INTERENV_PASSPHRASE="your-argon2id-passphrase" -e INTERENV_CI=1 my-app
```
