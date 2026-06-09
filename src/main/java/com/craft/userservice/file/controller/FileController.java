package com.craft.userservice.file.controller;

import java.time.Duration;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.craft.userservice.file.dto.FileDownloadUrlResponseDto;
import com.craft.userservice.file.dto.FileMetadataResponseDto;
import com.craft.userservice.file.exception.FileStorageException;
import com.craft.userservice.file.model.FileMetadata;
import com.craft.userservice.file.repository.FileMetadataRepository;
import com.craft.userservice.file.service.FileStorageService;
import com.craft.userservice.user.model.User;
import com.craft.userservice.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {
    private static final Duration DOWNLOAD_URL_EXPIRATION = Duration.ofMinutes(10);

    private final FileStorageService fileStorageService;
    private final UserRepository userRepository;
    private final FileMetadataRepository fileMetadataRepository;
    private final S3Presigner s3Presigner;

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file, Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        try {
            String email = (String) authentication.getPrincipal();
            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
            }

            FileMetadataResponseDto responseDto = fileStorageService.uploadFile(file, user.getId());
            return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
        } catch (FileStorageException e) {
            HttpStatus status = isStorageFailure(e) ? HttpStatus.INTERNAL_SERVER_ERROR : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
        }
    }

    @GetMapping("/my")
    public ResponseEntity<?> getMyFiles(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        String email = (String) authentication.getPrincipal();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        List<FileMetadataResponseDto> files = fileMetadataRepository
                .findByUploadedByUserIdOrderByCreatedAtDesc(user.getId())
                .stream()
                .map(this::toResponseDto)
                .toList();

        return ResponseEntity.ok(files);
    }

    @GetMapping("/{id}/download-url")
    public ResponseEntity<?> getDownloadUrl(@PathVariable String id, Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        String email = (String) authentication.getPrincipal();
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        FileMetadata metadata = fileMetadataRepository.findById(id).orElse(null);
        if (metadata == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("File not found");
        }

        if (!user.getId().equals(metadata.getUploadedByUserId())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
        }

        if (!StringUtils.hasText(metadata.getBucket()) || !StringUtils.hasText(metadata.getS3Key())) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File storage metadata is incomplete");
        }

        try {
            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(metadata.getBucket())
                    .key(metadata.getS3Key())
                    .build();

            GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
                    .signatureDuration(DOWNLOAD_URL_EXPIRATION)
                    .getObjectRequest(getObjectRequest)
                    .build();

            PresignedGetObjectRequest presignedRequest = s3Presigner.presignGetObject(presignRequest);

            return ResponseEntity.ok(FileDownloadUrlResponseDto.builder()
                    .id(metadata.getId())
                    .originalFilename(metadata.getOriginalFilename())
                    .downloadUrl(presignedRequest.url().toString())
                    .build());
        } catch (SdkClientException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Could not generate download URL");
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
                .status(metadata.getStatus())
                .createdAt(metadata.getCreatedAt())
                .updatedAt(metadata.getUpdatedAt())
                .build();
    }

    private boolean isStorageFailure(FileStorageException exception) {
        return exception.getCause() != null;
    }
}
