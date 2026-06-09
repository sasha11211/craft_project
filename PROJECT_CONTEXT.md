# Project Context for Codex

This file describes the current repository and how Codex should continue development.

## Repository Summary

The current repository is a Java Spring Boot project for the `users-service` backend service.

It is not yet a full multi-module marketplace repository. Treat it as the current User Service that will later be part of a larger microservice architecture.

## Business Direction

The broader product is planned as a marketplace platform for craft food in Israel.

Future platform capabilities may include:

- customer accounts
- seller/producer accounts
- product management
- orders
- business requests
- file uploads
- documents/certificates/invoices
- communication between customers and producers

The current codebase should not be over-expanded into all of these services yet. Continue incrementally.

## Current Codebase Facts

Current Maven artifact:

```text
users-service
```

Current Java version:

```text
21
```

Current Spring Boot version:

```text
3.5.4
```

Current persistence:

```text
MongoDB
```

Current main package:

```text
com.craft.userservice
```

Existing application areas:

```text
configuration
jwt
security
user
```

## Existing User/Auth Design

The project already contains user/auth logic.

Important current conventions:

- controllers return `ResponseEntity<?>`
- user auth base path is `/api/user`
- registration endpoint is `/api/user/auth/register`
- login endpoint is `/api/user/auth/login`
- refresh endpoint is `/api/user/auth/refresh`
- current user endpoint is `/api/user/current`
- MongoDB is used for users and refresh tokens
- roles include customer/seller style roles
- JWT cookies are used in the existing service logic

Do not rewrite this logic while implementing file storage.

## Current Development Focus

Add file storage to the existing `users-service`.

The first implementation can live inside this service. Later, it may be extracted into a separate Upload/File Service.

Recommended package root:

```text
com.craft.userservice.file
```

## File Storage Use Cases

Uploaded files should later support these use cases:

- user avatar/profile files
- seller/producer documents
- product images
- product/request attachments
- invoices
- certificates
- order attachments
- general documents

## Storage Strategy

Use Amazon S3 for binary file storage.

Use MongoDB only for file metadata.

Do not store file bytes in MongoDB.

## Recommended Metadata Model

Create a Mongo document for file metadata.

Suggested class name:

```java
FileMetadata
```

Suggested fields:

```java
private String id;
private String originalFileName;
private String storedFileName;
private String contentType;
private Long size;
private String bucket;
private String objectKey;
private String publicUrl;
private String ownerUserId;
private FileRelatedEntityType relatedEntityType;
private String relatedEntityId;
private Instant createdAt;
private Instant updatedAt;
private Boolean deleted;
private Instant deletedAt;
```

Use MongoDB annotations similar to the existing user model style.

Suggested collection:

```text
file_metadata
```

## Recommended Relation Enum

```java
public enum FileRelatedEntityType {
    USER_PROFILE,
    PRODUCT,
    ORDER,
    BUSINESS_REQUEST,
    PRODUCER_DOCUMENT,
    CERTIFICATE,
    INVOICE,
    OTHER
}
```

## Recommended DTOs

Suggested request/response DTOs:

```text
FileUploadResponseDto
FileMetadataResponseDto
PresignedUrlResponseDto
```

Upload endpoint can use `@RequestParam` for multipart data instead of a JSON request body.

## Recommended Upload Endpoint

```http
POST /api/files/upload
Content-Type: multipart/form-data
```

Request params:

```text
file
relatedEntityType
relatedEntityId
```

Possible response:

```json
{
  "id": "file-metadata-id",
  "originalFileName": "photo.jpg",
  "contentType": "image/jpeg",
  "size": 234567,
  "objectKey": "uploads/PRODUCT/123/2026/05/uuid-photo.jpg",
  "url": "https://...",
  "createdAt": "2026-05-11T10:00:00Z"
}
```

## Authentication for File Endpoints

Default assumption: file upload should require authentication.

Use the existing `Authentication` object in the controller where possible.

If extracting `ownerUserId` from `Authentication` is unclear, implement the file logic with a TODO and keep the API ready for ownership checks.

Do not make all file endpoints public by default.

## Validation Rules

First version should validate:

- file must not be empty
- file size must be below configured max size
- content type must be allowed
- original filename must be sanitized
- related entity type must be valid

Recommended first allowed content types:

```text
image/jpeg
image/png
image/webp
application/pdf
```

## Error Handling

Recommended HTTP responses:

```text
400 BAD_REQUEST - empty file or invalid parameters
404 NOT_FOUND - metadata not found
413 PAYLOAD_TOO_LARGE - file too large
415 UNSUPPORTED_MEDIA_TYPE - unsupported content type
500 INTERNAL_SERVER_ERROR - S3/storage failure
```

## Security Notes

Secrets must not be committed to GitHub.

Use environment variables for:

- MongoDB URI
- JWT secret
- AWS access key
- AWS secret key
- AWS region
- S3 bucket

## Important Instruction

Codex should work in small steps. It should not restructure the whole repository or convert the project to a multi-module architecture unless a future task explicitly asks for it.
