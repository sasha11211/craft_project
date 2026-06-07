package com.craft.userservice.file.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.craft.userservice.file.model.FileMetadata;

public interface FileMetadataRepository extends MongoRepository<FileMetadata, String> {

}
