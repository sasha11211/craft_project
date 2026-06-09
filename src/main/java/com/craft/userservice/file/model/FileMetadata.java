package com.craft.userservice.file.model;

import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import com.craft.userservice.file.enums.FileStorageStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "file_metadata")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FileMetadata {
    @Id
    private String id;

    @Indexed
    private String uploadedByUserId;
    private String originalFilename;
    private String contentType;
    private Long size;
    private String bucket;
    @Indexed(unique = true)
    private String s3Key;
    private String publicUrl;
    private FileStorageStatus status;
    private Instant createdAt;
    private Instant updatedAt;
}
