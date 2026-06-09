package com.craft.userservice.file.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;

import com.craft.userservice.file.configuration.S3Properties;
import com.craft.userservice.file.dto.FileMetadataResponseDto;
import com.craft.userservice.file.enums.FileStorageStatus;
import com.craft.userservice.file.exception.FileStorageException;
import com.craft.userservice.file.model.FileMetadata;
import com.craft.userservice.file.repository.FileMetadataRepository;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * Service-layer tests only. TODO: add content-type validation tests when
 * S3FileStorageService validates allowed content types.
 */
@ExtendWith(MockitoExtension.class)
class S3FileStorageServiceTest {
    private static final String BUCKET = "test-bucket";
    private static final String PUBLIC_BASE_URL = "https://cdn.example.test";
    private static final String USER_ID = "user-123";

    @Mock
    private S3Client s3Client;

    @Mock
    private FileMetadataRepository fileMetadataRepository;

    private S3FileStorageService service;

    @BeforeEach
    void setUp() {
        S3Properties s3Properties = new S3Properties();
        s3Properties.setBucket(BUCKET);
        s3Properties.setPublicBaseUrl(PUBLIC_BASE_URL);
        s3Properties.setMaxFileSizeMb(1);

        service = new S3FileStorageService(s3Client, s3Properties, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenFileIsEmpty_fails() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "empty.png",
                "image/png",
                new byte[0]);

        assertThatThrownBy(() -> service.uploadFile(file, USER_ID))
                .isInstanceOf(FileStorageException.class)
                .hasMessage("File must not be empty.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenFileIsOversized_fails() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "large.png",
                "image/png",
                new byte[(1024 * 1024) + 1]);

        assertThatThrownBy(() -> service.uploadFile(file, USER_ID))
                .isInstanceOf(FileStorageException.class)
                .hasMessage("File size exceeds the configured maximum.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenValid_callsS3PutObject() {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        when(fileMetadataRepository.save(any(FileMetadata.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.uploadFile(file, USER_ID);

        ArgumentCaptor<PutObjectRequest> requestCaptor = ArgumentCaptor.forClass(PutObjectRequest.class);
        verify(s3Client).putObject(requestCaptor.capture(), any(RequestBody.class));

        PutObjectRequest request = requestCaptor.getValue();
        assertThat(request.bucket()).isEqualTo(BUCKET);
        assertThat(request.key()).startsWith("users/user-123/uploads/");
        assertThat(request.key()).endsWith("-photo.png");
        assertThat(request.contentType()).isEqualTo("image/png");
        assertThat(request.contentLength()).isEqualTo(file.getSize());
    }

    @Test
    void uploadFile_whenValid_savesFileMetadata() {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        when(fileMetadataRepository.save(any(FileMetadata.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.uploadFile(file, USER_ID);

        ArgumentCaptor<FileMetadata> metadataCaptor = ArgumentCaptor.forClass(FileMetadata.class);
        verify(fileMetadataRepository).save(metadataCaptor.capture());

        FileMetadata metadata = metadataCaptor.getValue();
        assertThat(metadata.getUploadedByUserId()).isEqualTo(USER_ID);
        assertThat(metadata.getOriginalFilename()).isEqualTo("photo.png");
        assertThat(metadata.getContentType()).isEqualTo("image/png");
        assertThat(metadata.getSize()).isEqualTo(file.getSize());
        assertThat(metadata.getBucket()).isEqualTo(BUCKET);
        assertThat(metadata.getS3Key()).startsWith("users/user-123/uploads/");
        assertThat(metadata.getPublicUrl()).isEqualTo(PUBLIC_BASE_URL + "/" + metadata.getS3Key());
        assertThat(metadata.getStatus()).isEqualTo(FileStorageStatus.UPLOADED);
        assertThat(metadata.getCreatedAt()).isNotNull();
        assertThat(metadata.getUpdatedAt()).isNotNull();
    }

    @Test
    void uploadFile_whenValid_returnsResponseDto() {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        when(fileMetadataRepository.save(any(FileMetadata.class))).thenAnswer(invocation -> {
            FileMetadata metadata = invocation.getArgument(0);
            metadata.setId("file-123");
            return metadata;
        });

        FileMetadataResponseDto response = service.uploadFile(file, USER_ID);

        assertThat(response.getId()).isEqualTo("file-123");
        assertThat(response.getUploadedByUserId()).isEqualTo(USER_ID);
        assertThat(response.getOriginalFilename()).isEqualTo("photo.png");
        assertThat(response.getContentType()).isEqualTo("image/png");
        assertThat(response.getSize()).isEqualTo(file.getSize());
        assertThat(response.getBucket()).isEqualTo(BUCKET);
        assertThat(response.getS3Key()).startsWith("users/user-123/uploads/");
        assertThat(response.getPublicUrl()).isEqualTo(PUBLIC_BASE_URL + "/" + response.getS3Key());
        assertThat(response.getStatus()).isEqualTo(FileStorageStatus.UPLOADED);
        assertThat(response.getCreatedAt()).isNotNull();
        assertThat(response.getUpdatedAt()).isNotNull();
    }

    @Test
    void deleteFile_whenMetadataIsValid_callsS3DeleteObject() {
        FileMetadata metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        service.deleteFile(metadata);

        ArgumentCaptor<DeleteObjectRequest> requestCaptor = ArgumentCaptor.forClass(DeleteObjectRequest.class);
        verify(s3Client).deleteObject(requestCaptor.capture());

        DeleteObjectRequest request = requestCaptor.getValue();
        assertThat(request.bucket()).isEqualTo(BUCKET);
        assertThat(request.key()).isEqualTo("users/user-123/uploads/2026/06/file-photo.png");
    }

    @Test
    void deleteFile_whenMetadataIsValid_marksMetadataAsDeleted() {
        FileMetadata metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        service.deleteFile(metadata);

        assertThat(metadata.getStatus()).isEqualTo(FileStorageStatus.DELETED);
        assertThat(metadata.getUpdatedAt()).isNotNull();
    }

    @Test
    void deleteFile_whenMetadataIsValid_savesUpdatedMetadata() {
        FileMetadata metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        service.deleteFile(metadata);

        ArgumentCaptor<FileMetadata> metadataCaptor = ArgumentCaptor.forClass(FileMetadata.class);
        verify(fileMetadataRepository).save(metadataCaptor.capture());
        assertThat(metadataCaptor.getValue()).isSameAs(metadata);
        assertThat(metadataCaptor.getValue().getStatus()).isEqualTo(FileStorageStatus.DELETED);
    }

    private MockMultipartFile validFile() {
        return new MockMultipartFile(
                "file",
                "photo.png",
                "image/png",
                "image bytes".getBytes());
    }

    private FileMetadata storedMetadata() {
        return FileMetadata.builder()
                .id("file-123")
                .uploadedByUserId(USER_ID)
                .originalFilename("photo.png")
                .contentType("image/png")
                .size(11L)
                .bucket(BUCKET)
                .s3Key("users/user-123/uploads/2026/06/file-photo.png")
                .status(FileStorageStatus.UPLOADED)
                .build();
    }
}
