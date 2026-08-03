package com.craft.userservice.file.dto;

import java.time.Instant;

import com.craft.userservice.file.enums.FileStorageStatus;
import com.craft.userservice.file.enums.FileUsageType;
import com.craft.userservice.file.enums.FileVisibility;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FileMetadataResponseDto {
    private String id;
    private String uploadedByUserId;
    private String originalFilename;
    private String contentType;
    private Long size;
    private String bucket;
    private String s3Key;
    private String publicUrl;
    private FileVisibility visibility;
    private FileUsageType usageType;
    private FileStorageStatus status;
    private Instant createdAt;
    private Instant updatedAt;
}
