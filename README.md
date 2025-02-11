# PHP JWT API Setup Guide

This is a simple PHP API with JWT authentication, running in a LAMP stack using Docker.

## Prerequisites

- Docker
- Docker Compose
- curl (for testing)

## Setup Instructions

1. Clone the repository and navigate to the project directory

2. Build and start the Docker containers:
```bash
docker compose build
docker compose up -d
```

3. Verify the services are running:
- API: http://localhost:8080
- PHPMyAdmin: http://localhost:8083

## Testing the API

### 1. Register a New User

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "mypassword123"
  }'
```

Expected response:
```json
{
    "message": "User registered successfully"
}
```

### 2. Login

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "mypassword123"
  }'
```

Expected response:
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### 3. Get User Details

```bash
curl -X GET http://localhost:8080/user \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

Replace `YOUR_JWT_TOKEN_HERE` with the token received from the login response.

Expected response:
```json
{
    "user": {
        "id": 1,
        "username": "testuser",
        "email": "test@example.com"
    }
}
```

## Testing Error Cases

### 1. Register with Existing Email
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2",
    "email": "test@example.com",
    "password": "password123"
  }'
```

### 2. Login with Wrong Credentials
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "wrongpassword"
  }'
```

### 3. Access Protected Route Without Token
```bash
curl -X GET http://localhost:8080/user
```

## Cleanup

To stop and remove all containers:
```bash
docker-compose down
```

To also remove the persistent MySQL data:
```bash
docker-compose down -v
```