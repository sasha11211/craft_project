package com.craft.userservice.file.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.craft.userservice.file.model.FileMetadata;

public interface FileMetadataRepository extends MongoRepository<FileMetadata, String> {
    List<FileMetadata> findByUploadedByUserIdOrderByCreatedAtDesc(String uploadedByUserId);

    Optional<FileMetadata> findByUploadedByUserIdAndPublicUrl(String uploadedByUserId, String publicUrl);
}
