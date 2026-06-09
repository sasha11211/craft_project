# Codex Tasks

Current status: Amazon S3-backed file storage is implemented in the `users-service` Spring Boot project. This document now tracks what is complete, what API surface exists, and what remains for later hardening or product expansion.

## Completed Tasks

- Moved secrets out of committed configuration and into environment variables.
- Added the AWS SDK S3 dependency.
- Added S3 configuration with `S3Config` and `S3Properties`.
- Added an `S3Client` bean.
- Added an `S3Presigner` bean for temporary download links.
- Added the `FileMetadata` MongoDB model.
- Added `FileMetadataRepository`.
- Added `FileStorageService`.
- Added `S3FileStorageService`.
- Kept the S3 bucket private.
- Implemented private downloads through presigned URLs.
- Implemented soft delete metadata handling.
- Implemented S3 object deletion during file delete.

## Current Implemented API

### Upload File

```http
POST /api/files/upload
Content-Type: multipart/form-data
```

Uploads a file to the private S3 bucket and stores metadata in MongoDB.

### List My Files

```http
GET /api/files/my
```

Returns the authenticated user's non-deleted file metadata.

### Get Download URL

```http
GET /api/files/{id}/download-url
```

Returns a temporary presigned URL for downloading a private file.

### Delete File

```http
DELETE /api/files/{id}
```

Soft deletes the file metadata and deletes the corresponding S3 object.

## Remaining Tasks

- Add tests for file upload validation, S3 key generation, owner checks, and delete logic.
- Add a metadata lookup endpoint only if still needed.
- Add support for file usage types like `AVATAR`, `PRODUCT_IMAGE`, and `SELLER_LOGO` later.
- Add `PUBLIC` / `PRIVATE` visibility later.
- Add CloudFront or public URL support later.
- Add frontend integration notes later.
