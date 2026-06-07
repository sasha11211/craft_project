package com.craft.userservice.file.service;

import org.springframework.web.multipart.MultipartFile;

import com.craft.userservice.file.dto.FileMetadataResponseDto;

public interface FileStorageService {
    FileMetadataResponseDto uploadFile(MultipartFile file, String uploadedByUserId);
}
