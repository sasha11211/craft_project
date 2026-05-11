# Codex Tasks

Current priority: add Amazon S3 file storage to the existing `users-service` Spring Boot project.

Run tasks one by one. Do not implement all tasks at once unless explicitly requested.

## Task 0: Move Secrets Out of application.properties

### Goal

Replace committed sensitive values with environment-variable based configuration.

### Requirements

- Do not keep real MongoDB credentials in `application.properties`.
- Do not keep weak/default JWT secret in `application.properties`.
- Use placeholders such as `${MONGODB_URI}` and `${JWT_SECRET}`.
- Keep safe default values only for non-secret local settings.

### Suggested properties

```properties
spring.data.mongodb.uri=${MONGODB_URI}
security.jwt.secret=${JWT_SECRET}
```

### Important

Do this before deploying further changes.

---

## Task 1: Add AWS SDK Dependency

### Goal

Add the required AWS SDK v2 dependency for S3.

### Requirements

Update `pom.xml`.

Suggested dependency:

```xml
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>s3</artifactId>
</dependency>
```

If Maven requires a version, use an AWS SDK BOM or a stable explicit version.

Do not remove existing dependencies.

---

## Task 2: Add S3 Configuration Classes

### Goal

Create configuration for Amazon S3 access.

### Suggested package

```text
com.craft.userservice.file.configuration
```

### Suggested files

```text
S3Config.java
S3Properties.java
```

### Required properties

```properties
aws.s3.region=${AWS_REGION}
aws.s3.bucket=${AWS_S3_BUCKET}
aws.s3.public-base-url=${AWS_S3_PUBLIC_BASE_URL:}
aws.s3.max-file-size-mb=${AWS_S3_MAX_FILE_SIZE_MB:10}
```

### Requirements

- Use `@ConfigurationProperties` for S3 settings.
- Register configuration properties correctly.
- Create an `S3Client` bean.
- Do not hardcode AWS credentials.
- Let AWS SDK use the default credentials provider chain.

---

## Task 3: Add File Metadata Model and Repository

### Goal

Create MongoDB metadata storage for uploaded files.

### Suggested package

```text
com.craft.userservice.file
```

### Suggested files

```text
model/FileMetadata.java
enums/FileRelatedEntityType.java
repository/FileMetadataRepository.java
```

### FileMetadata fields

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

### Repository

```java
public interface FileMetadataRepository extends MongoRepository<FileMetadata, String> {
}
```

Add useful query methods only if needed.

---

## Task 4: Add Upload Response DTO

### Goal

Create DTOs for file API responses.

### Suggested package

```text
com.craft.userservice.file.dto
```

### Suggested file

```text
FileUploadResponseDto.java
```

### Suggested fields

```java
private String id;
private String originalFileName;
private String contentType;
private Long size;
private String objectKey;
private String url;
private Instant createdAt;
```

Use Lombok if consistent with the current project.

---

## Task 5: Add File Storage Service

### Goal

Upload files to S3 and save metadata in MongoDB.

### Suggested package

```text
com.craft.userservice.file.service
```

### Suggested files

```text
FileStorageService.java
S3FileStorageService.java
```

### Suggested method

```java
FileUploadResponseDto uploadFile(
    MultipartFile file,
    FileRelatedEntityType relatedEntityType,
    String relatedEntityId,
    String ownerUserId
);
```

### Requirements

The service should:

- reject empty files
- validate max file size from configuration
- validate allowed content types
- sanitize original filename
- generate a UUID-based stored filename
- generate S3 object key
- upload to S3 using `S3Client.putObject`
- save metadata in MongoDB
- return `FileUploadResponseDto`

### Allowed content types for first version

```text
image/jpeg
image/png
image/webp
application/pdf
```

### Object key format

```text
uploads/{relatedEntityType}/{relatedEntityId}/{yyyy}/{MM}/{uuid}-{safeOriginalFileName}
```

---

## Task 6: Add File Controller

### Goal

Expose REST endpoints for file upload and metadata lookup.

### Suggested package

```text
com.craft.userservice.file.controller
```

### Suggested file

```text
FileController.java
```

### Upload endpoint

```http
POST /api/files/upload
Content-Type: multipart/form-data
```

### Request params

```text
file
relatedEntityType
relatedEntityId
```

### Requirements

- Return `ResponseEntity<?>`.
- Use the existing `Authentication` object if available.
- Try to set `ownerUserId` from the authenticated user.
- Do not make upload public unless explicitly requested.

---

## Task 7: Add Metadata Lookup Endpoint

### Goal

Return file metadata by ID.

### Endpoint

```http
GET /api/files/{id}
```

### Requirements

- Return metadata DTO.
- Return 404 if not found.
- Do not return private implementation details unnecessarily.

---

## Task 8: Add Pre-Signed Download URL Endpoint

### Goal

Generate temporary access links for private files.

### Endpoint

```http
GET /api/files/{id}/download-url
```

### Suggested response

```json
{
  "url": "https://signed-url...",
  "expiresInMinutes": 15
}
```

### Requirements

- Use `S3Presigner`.
- Default expiration: 15 minutes.
- Return 404 if metadata does not exist.
- Add permission checks later if not ready now.

---

## Task 9: Add Delete Logic

### Goal

Delete uploaded files safely.

### Endpoint

```http
DELETE /api/files/{id}
```

### Requirements

- Delete S3 object.
- Prefer soft delete metadata first: set `deleted=true` and `deletedAt`.
- Add TODO for ownership/permission check if not implemented yet.

---

## Task 10: Add Basic Tests

### Goal

Add tests around file validation and object-key generation.

### Suggested tests

- empty file fails
- unsupported content type fails
- oversized file fails
- object key contains relation type and related ID
- metadata is saved after successful upload

Use mocks for S3 client where possible.
