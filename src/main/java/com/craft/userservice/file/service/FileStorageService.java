package com.craft.userservice.file.service;

import org.springframework.web.multipart.MultipartFile;

import com.craft.userservice.file.dto.FileMetadataResponseDto;
import com.craft.userservice.file.model.FileMetadata;

public interface FileStorageService {
    FileMetadataResponseDto uploadFile(MultipartFile file, String uploadedByUserId);

    FileMetadataResponseDto uploadAvatar(MultipartFile file, String uploadedByUserId);

    void deleteFile(FileMetadata metadata);
}
