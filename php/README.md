# InterEnv PHP SDK

Hardware-Enclave Protected Secrets for PHP, Laravel, and Symfony Applications. Zero Plaintext `.env` on Disk. Built by **Interlayer**.

## Installation

```bash
composer require bharathcoorg/interenv
```

Ensure the native `interenv` CLI is installed (`cargo install interenv` or `npm install -g interenv`).

## Quickstart

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use InterEnv\InterEnv;

// Directly loads secrets into $_ENV, $_SERVER, and putenv() in memory
InterEnv::load();

$apiKey = getenv('STRIPE_SECRET_KEY');
echo "Secure secret loaded in memory without disk leakage!";
```

## Programmatic Access

```php
// Retrieve a single secret
$dbPass = InterEnv::get('DB_PASSWORD');

// Get all secrets
$all = InterEnv::all();
```
