package com.craft.userservice.file.service;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.craft.userservice.file.configuration.S3Properties;
import com.craft.userservice.file.dto.FileMetadataResponseDto;
import com.craft.userservice.file.enums.FileStorageStatus;
import com.craft.userservice.file.enums.FileUsageType;
import com.craft.userservice.file.enums.FileVisibility;
import com.craft.userservice.file.exception.FileStorageException;
import com.craft.userservice.file.model.FileMetadata;
import com.craft.userservice.file.repository.FileMetadataRepository;

import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

@Service
public class S3FileStorageService implements FileStorageService {
    private static final long BYTES_PER_MB = 1024L * 1024L;
    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/jpeg",
            "image/png",
            "image/webp",
            "application/pdf");
    private static final Set<String> ALLOWED_AVATAR_CONTENT_TYPES = Set.of(
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/svg+xml");

    private final S3Client s3Client;
    private final S3Properties s3Properties;
    private final FileMetadataRepository fileMetadataRepository;

    public S3FileStorageService(
            S3Client s3Client,
            S3Properties s3Properties,
            FileMetadataRepository fileMetadataRepository) {
        this.s3Client = s3Client;
        this.s3Properties = s3Properties;
        this.fileMetadataRepository = fileMetadataRepository;
    }

    @Override
    public FileMetadataResponseDto uploadFile(MultipartFile file, String uploadedByUserId) {
        validateUploadRequest(file, uploadedByUserId, ALLOWED_CONTENT_TYPES);

        String originalFilename = sanitizeFilename(file.getOriginalFilename());
        String s3Key = buildPrivateS3Key(uploadedByUserId, originalFilename);
        FileMetadata savedMetadata = uploadAndSaveMetadata(
                file,
                uploadedByUserId,
                originalFilename,
                s3Key,
                null,
                FileVisibility.PRIVATE,
                FileUsageType.DOCUMENT);

        return toResponseDto(savedMetadata);
    }

    @Override
    public FileMetadataResponseDto uploadAvatar(MultipartFile file, String uploadedByUserId) {
        validateUploadRequest(file, uploadedByUserId, ALLOWED_AVATAR_CONTENT_TYPES);

        if (!StringUtils.hasText(s3Properties.getPublicBaseUrl())) {
            throw new FileStorageException("Public file base URL is not configured.");
        }

        String originalFilename = sanitizeFilename(file.getOriginalFilename());
        String s3Key = buildPublicAvatarS3Key(uploadedByUserId, originalFilename);
        FileMetadata savedMetadata = uploadAndSaveMetadata(
                file,
                uploadedByUserId,
                originalFilename,
                s3Key,
                buildPublicUrl(s3Key),
                FileVisibility.PUBLIC,
                FileUsageType.AVATAR);

        return toResponseDto(savedMetadata);
    }

    private FileMetadata uploadAndSaveMetadata(
            MultipartFile file,
            String uploadedByUserId,
            String originalFilename,
            String s3Key,
            String publicUrl,
            FileVisibility visibility,
            FileUsageType usageType) {
        String bucket = s3Properties.getBucket();

        try (InputStream inputStream = file.getInputStream()) {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(s3Key)
                    .contentType(file.getContentType())
                    .contentLength(file.getSize())
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromInputStream(inputStream, file.getSize()));
        } catch (IOException | S3Exception | SdkClientException ex) {
            throw new FileStorageException("Could not upload file. Please try again later.", ex);
        }

        Instant now = Instant.now();
        FileMetadata metadata = FileMetadata.builder()
                .uploadedByUserId(uploadedByUserId)
                .originalFilename(originalFilename)
                .contentType(file.getContentType())
                .size(file.getSize())
                .bucket(bucket)
                .s3Key(s3Key)
                .publicUrl(publicUrl)
                .visibility(visibility)
                .usageType(usageType)
                .status(FileStorageStatus.UPLOADED)
                .createdAt(now)
                .updatedAt(now)
                .build();

        try {
            return fileMetadataRepository.save(metadata);
        } catch (RuntimeException ex) {
            tryDeleteUploadedObject(bucket, s3Key);
            throw ex;
        }
    }

    @Override
    public void deleteFile(FileMetadata metadata) {
        if (metadata == null) {
            throw new FileStorageException("File metadata is required.");
        }

        if (!StringUtils.hasText(metadata.getBucket()) || !StringUtils.hasText(metadata.getS3Key())) {
            throw new FileStorageException("File storage metadata is incomplete.");
        }

        try {
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(metadata.getBucket())
                    .key(metadata.getS3Key())
                    .build();

            s3Client.deleteObject(deleteObjectRequest);
        } catch (S3Exception | SdkClientException ex) {
            throw new FileStorageException("Could not delete file. Please try again later.", ex);
        }

        metadata.setStatus(FileStorageStatus.DELETED);
        metadata.setUpdatedAt(Instant.now());
        fileMetadataRepository.save(metadata);
    }

    private void validateUploadRequest(MultipartFile file, String uploadedByUserId, Set<String> allowedContentTypes) {
        if (!StringUtils.hasText(uploadedByUserId)) {
            throw new FileStorageException("Uploaded user id is required.");
        }

        if (file == null || file.isEmpty()) {
            throw new FileStorageException("File must not be empty.");
        }

        if (!StringUtils.hasText(s3Properties.getBucket())) {
            throw new FileStorageException("File storage bucket is not configured.");
        }

        long maxFileSizeBytes = s3Properties.getMaxFileSizeMb() * BYTES_PER_MB;
        if (maxFileSizeBytes <= 0) {
            throw new FileStorageException("Maximum file size is not configured correctly.");
        }

        if (file.getSize() > maxFileSizeBytes) {
            throw new FileStorageException("File size exceeds the configured maximum.");
        }

        String contentType = file.getContentType();
        if (!StringUtils.hasText(contentType)) {
            throw new FileStorageException("File content type is required.");
        }

        if (!allowedContentTypes.contains(contentType)) {
            throw new FileStorageException("File content type is not supported.");
        }
    }

    private String buildPrivateS3Key(String uploadedByUserId, String sanitizedFilename) {
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        return "users/%s/uploads/%04d/%02d/%s-%s".formatted(
                sanitizePathSegment(uploadedByUserId),
                today.getYear(),
                today.getMonthValue(),
                UUID.randomUUID(),
                sanitizedFilename);
    }

    private String buildPublicAvatarS3Key(String uploadedByUserId, String sanitizedFilename) {
        return "public/users/%s/avatar/%s-%s".formatted(
                sanitizePathSegment(uploadedByUserId),
                UUID.randomUUID(),
                sanitizedFilename);
    }

    private String sanitizeFilename(String filename) {
        String cleanFilename = StringUtils.hasText(filename) ? filename : "file";
        cleanFilename = cleanFilename.replace('\\', '/');
        cleanFilename = cleanFilename.substring(cleanFilename.lastIndexOf('/') + 1).trim();
        cleanFilename = cleanFilename.replaceAll("[^a-zA-Z0-9._-]", "_");
        cleanFilename = cleanFilename.replaceAll("_+", "_");

        if (!StringUtils.hasText(cleanFilename) || ".".equals(cleanFilename) || "..".equals(cleanFilename)) {
            return "file";
        }

        return cleanFilename;
    }

    private String sanitizePathSegment(String value) {
        return value.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private String buildPublicUrl(String s3Key) {
        String publicBaseUrl = s3Properties.getPublicBaseUrl();
        if (!StringUtils.hasText(publicBaseUrl)) {
            return null;
        }

        return publicBaseUrl.endsWith("/") ? publicBaseUrl + s3Key : publicBaseUrl + "/" + s3Key;
    }

    private void tryDeleteUploadedObject(String bucket, String s3Key) {
        try {
            DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                    .bucket(bucket)
                    .key(s3Key)
                    .build();
            s3Client.deleteObject(deleteObjectRequest);
        } catch (S3Exception | SdkClientException ignored) {
        }
    }

    private FileMetadataResponseDto toResponseDto(FileMetadata metadata) {
        return FileMetadataResponseDto.builder()
                .id(metadata.getId())
                .uploadedByUserId(metadata.getUploadedByUserId())
                .originalFilename(metadata.getOriginalFilename())
                .contentType(metadata.getContentType())
                .size(metadata.getSize())
                .bucket(metadata.getBucket())
                .s3Key(metadata.getS3Key())
                .publicUrl(metadata.getPublicUrl())
                .visibility(metadata.getVisibility())
                .usageType(metadata.getUsageType())
                .status(metadata.getStatus())
                .createdAt(metadata.getCreatedAt())
                .updatedAt(metadata.getUpdatedAt())
                .build();
    }
}
