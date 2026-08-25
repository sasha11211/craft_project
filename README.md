# Craft Project - Users Service

This repository currently contains a Spring Boot backend service named `users-service`.

Current development focus: add file storage support using Amazon S3 without rewriting existing authentication, JWT, CORS, or user logic.

## Current Service

The current branch is focused on the User Service.

Main responsibilities already present in the codebase:

- user registration
- user login
- JWT access token handling
- refresh token handling
- current user endpoint
- user update endpoint
- role add endpoint
- MongoDB persistence
- Spring Security configuration

## Current Technology Stack

- Java 21
- Spring Boot 3.5.4
- Maven
- Spring Web
- Spring Security
- Spring Data MongoDB
- Validation
- JJWT 0.12.5
- ModelMapper
- Lombok
- Docker
- Render deployment support

## Current Package Structure

Current main package:

```text
com.craft.userservice
```

Important existing packages:

```text
com.craft.userservice.configuration
com.craft.userservice.jwt
com.craft.userservice.security
com.craft.userservice.user
```

When adding file storage, keep the same package style.

Recommended new package:

```text
com.craft.userservice.file
```

Suggested subpackages:

```text
com.craft.userservice.file.configuration
com.craft.userservice.file.controller
com.craft.userservice.file.dto
com.craft.userservice.file.enums
com.craft.userservice.file.exception
com.craft.userservice.file.model
com.craft.userservice.file.repository
com.craft.userservice.file.service
```

## Current Auth API

Existing controller base path:

```http
/api/user
```

Known endpoints:

```http
POST /api/user/auth/register
POST /api/user/auth/login
POST /api/user/auth/refresh
POST /api/user/auth/logout
POST /api/user/auth/logout-all
GET  /api/user/current
PUT  /api/user/update
```

## File Storage Goal

Add a clean and isolated file storage module backed by Amazon S3.

First version should support:

- upload file to S3
- validate file size
- validate content type
- sanitize original filename
- generate safe S3 object key
- store metadata in MongoDB
- return upload response DTO
- get file metadata by ID
- optionally generate pre-signed download URL later
- delete file from S3 and metadata later

## Required Environment Variables

Example values only:

```env
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=eu-central-1
AWS_S3_BUCKET=
AWS_S3_PUBLIC_BASE_URL=
AWS_S3_MAX_FILE_SIZE_MB=10
```

The project should also move sensitive MongoDB and JWT values to environment variables.

## Recommended S3 Object Key Format

```text
uploads/{relatedEntityType}/{relatedEntityId}/{yyyy}/{MM}/{uuid}-{safeOriginalFileName}
```

Example:

```text
uploads/PRODUCT/64f1abc123/2026/05/9f7d2a-product-photo.jpg
```
