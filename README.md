# Craft Project - Users Service

`users-service` is a Spring Boot microservice for user accounts, cookie-based JWT authentication, refresh token rotation, user profile updates, and S3-backed file storage.

## Current Features

- User registration and login
- Password hashing with BCrypt
- JWT access token generation
- Refresh token rotation and revocation
- Auth cookies: `access_token` and `refresh_token`
- Current user profile endpoint
- User profile update endpoint
- MongoDB persistence for users, refresh tokens, and file metadata
- S3 upload support for private documents
- S3 upload support for public user avatars
- File metadata lookup
- Current user's file list
- Pre-signed S3 download URL generation
- File deletion from S3 with metadata status update
- Spring Security protection for private endpoints
- Health endpoint support for deployment platforms

## Tech Stack

- Java 21
- Spring Boot 3.5.4
- Maven
- Spring Web
- Spring Security
- Spring Data MongoDB
- Spring Validation
- AWS SDK for Java v2, S3
- JJWT 0.12.5
- ModelMapper
- Lombok
- Docker

## Project Structure

```text
src/main/java/com/craft/userservice
+-- configuration      # Spring, security, CORS, JWT, shared beans
+-- file               # S3 file storage module
+-- jwt                # Refresh token model, repository, and service
+-- security           # JWT utilities and auth filters
+-- user               # User API, service, DTOs, model, repository
```

## Requirements

- Java 21
- Maven, or the included Maven Wrapper
- MongoDB database
- AWS S3 bucket
- AWS credentials available through the AWS SDK default credentials provider chain

## Environment Variables

The service reads sensitive and environment-specific values from environment variables.

```env
MONGODB_URI=mongodb+srv://...
JWT_SECRET=your-long-secret
PORT=8080

AWS_REGION=eu-central-1
AWS_S3_BUCKET=your-bucket-name
AWS_S3_PUBLIC_BASE_URL=https://your-public-file-domain-or-bucket-url
AWS_S3_MAX_FILE_SIZE_MB=10

AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

Notes:

- `PORT` is optional. The default is `8080`.
- `AWS_S3_PUBLIC_BASE_URL` is required for avatar uploads because avatar files are returned as public URLs.
- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are not read directly by application properties. They are picked up by the AWS SDK.
- `JWT_SECRET` must be long enough for the signing algorithm used by the JWT utility.

## Run Locally

From the `users-service` directory:

```bash
./mvnw spring-boot:run
```

On Windows:

```bat
mvnw.cmd spring-boot:run
```

The service starts on:

```text
http://localhost:8080
```

## Build

```bash
./mvnw clean package
```

To skip tests:

```bash
./mvnw clean package -DskipTests
```

## Run With Docker

Build the image:

```bash
docker build -t users-service .
```

Run the container:

```bash
docker run --env-file .env -p 8080:8080 users-service
```

## Authentication

The service uses cookie-based authentication.

After successful registration or login, the response sets:

- `access_token`
- `refresh_token`

Both cookies are configured as:

- `HttpOnly`
- `Secure`
- `SameSite=None`
- `Path=/`

Because cookies are marked `Secure`, browser-based local testing may require HTTPS or adjusted client tooling.

## Public Auth API

Base path:

```text
/api/user
```

### Register

```http
POST /api/user/auth/register
Content-Type: application/json
```

Request body:

```json
{
  "email": "user@example.com",
  "password": "password123",
  "fullName": "Test User",
  "mobile": "+972501234567",
  "address": {
    "city": "Tel Aviv"
  }
}
```

Validation:

- `email` must be valid and unique.
- `mobile` must be unique and match E.164 style, for example `+972501234567`.
- `address.city` is required.

### Login

```http
POST /api/user/auth/login
Content-Type: application/json
```

Request body:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

### Refresh Tokens

```http
POST /api/user/auth/refresh
```

Uses the `refresh_token` cookie. On success, the service rotates the refresh token and sets new auth cookies.

## Protected User API

These endpoints require a valid `access_token` cookie.

### Get Current User

```http
GET /api/user/current
```

### Update Current User

```http
PUT /api/user/update
Content-Type: application/json
```

Request body:

```json
{
  "fullName": "Updated User",
  "mobile": "+972501234568",
  "address": {
    "city": "Haifa"
  }
}
```

Notes:

- `mobile` must remain unique.
- `avatarUrl` is intentionally preserved by the service during profile update.
- To change a user avatar, use `POST /api/files/avatar`.

### Logout Current Device

```http
POST /api/user/auth/logout
```

Uses the current `refresh_token` cookie, revokes it, and clears auth cookies.

### Logout All Devices

```http
POST /api/user/auth/logout-all
```

Revokes all refresh tokens for the current user and clears auth cookies.

## Protected File API

Base path:

```text
/api/files
```

All file endpoints require a valid `access_token` cookie.

### Upload Private File

```http
POST /api/files/upload
Content-Type: multipart/form-data
```

Form field:

```text
file
```

Supported content types:

- `image/jpeg`
- `image/png`
- `image/webp`
- `application/pdf`

Private files are stored with keys similar to:

```text
users/{userId}/uploads/{yyyy}/{MM}/{uuid}-{safeOriginalFilename}
```

The response contains file metadata, including `id`, `s3Key`, `visibility`, `usageType`, and `status`.

### Upload Avatar

```http
POST /api/files/avatar
Content-Type: multipart/form-data
```

Form field:

```text
file
```

Supported avatar content types:

- `image/jpeg`
- `image/png`
- `image/webp`
- `image/svg+xml`

Avatar files are stored with keys similar to:

```text
public/users/{userId}/avatar/{uuid}-{safeOriginalFilename}
```

On success:

- The file is uploaded to S3.
- Metadata is saved in MongoDB.
- The user's `avatarUrl` is updated.
- The previous stored avatar is deleted when possible.

### Get My Files

```http
GET /api/files/my
```

Returns non-deleted files uploaded by the current user, ordered by creation date descending.

### Get File Metadata

```http
GET /api/files/{id}
```

Returns metadata only if the file belongs to the current user and is not deleted.

### Get Download URL

```http
GET /api/files/{id}/download-url
```

Returns a pre-signed S3 download URL for the current user's file.

The generated URL expires after 10 minutes.

### Delete File

```http
DELETE /api/files/{id}
```

Deletes the object from S3 and updates its metadata status to `DELETED`.

## File Metadata

File metadata is stored in the MongoDB collection:

```text
file_metadata
```

Important fields:

- `uploadedByUserId`
- `originalFilename`
- `contentType`
- `size`
- `bucket`
- `s3Key`
- `publicUrl`
- `visibility`
- `usageType`
- `status`
- `createdAt`
- `updatedAt`

Current file visibility values:

- `PRIVATE`
- `PUBLIC`

Current file usage values:

- `DOCUMENT`
- `AVATAR`

Current file status values:

- `UPLOADED`
- `DELETED`

## Security Rules

Public endpoints:

```text
POST /api/user/auth/register
POST /api/user/auth/login
POST /api/user/auth/refresh
```

All other endpoints require authentication.

Unauthenticated requests return `401`.

Forbidden file access returns `403` when a user tries to access another user's file.

## Health

Actuator health endpoints are enabled for deployment checks:

```text
/actuator/health
```

## Tests

Run tests:

```bash
./mvnw test
```

On Windows:

```bat
mvnw.cmd test
```

Current test coverage includes the Spring Boot context test and S3 file storage service tests.

## Known Notes

- Auth is currently cookie-based, not bearer-token based.
- `AuthResponseDto` exists in the codebase, but current register/login responses set cookies and return user data.
- File upload validation is based on content type and configured maximum size.
- File deletion updates metadata to `DELETED`; deleted files are hidden from user file listings.
- S3 access and bucket policy must be configured outside the application.
