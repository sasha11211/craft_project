package com.craft.userservice.file.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

@ExtendWith(MockitoExtension.class)
class S3FileStorageServiceTest {
    private static final String BUCKET = "test-bucket";
    private static final String PUBLIC_BASE_URL = "https://cdn.example.test";
    private static final String USER_ID = "user-123";

    @Mock
    private S3Client s3Client;

    private Object fileMetadataRepository;
    private Object service;

    @BeforeEach
    void setUp() throws Exception {
        Object s3Properties = newInstance("com.craft.userservice.file.configuration.S3Properties");
        invoke(s3Properties, "setBucket", String.class, BUCKET);
        invoke(s3Properties, "setPublicBaseUrl", String.class, PUBLIC_BASE_URL);
        invoke(s3Properties, "setMaxFileSizeMb", long.class, 1L);

        Class<?> repositoryClass = type("com.craft.userservice.file.repository.FileMetadataRepository");
        fileMetadataRepository = org.mockito.Mockito.mock(repositoryClass);

        Constructor<?> constructor = type("com.craft.userservice.file.service.S3FileStorageService")
                .getConstructor(S3Client.class, s3Properties.getClass(), repositoryClass);
        service = constructor.newInstance(s3Client, s3Properties, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenFileIsEmpty_fails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "empty.png",
                "image/png",
                new byte[0]);

        assertThatThrownBy(() -> uploadFile(file))
                .isInstanceOf(runtimeException("com.craft.userservice.file.exception.FileStorageException"))
                .hasMessage("File must not be empty.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenFileIsOversized_fails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "large.png",
                "image/png",
                new byte[(1024 * 1024) + 1]);

        assertThatThrownBy(() -> uploadFile(file))
                .isInstanceOf(runtimeException("com.craft.userservice.file.exception.FileStorageException"))
                .hasMessage("File size exceeds the configured maximum.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenContentTypeIsUnsupported_fails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "notes.txt",
                "text/plain",
                "not allowed".getBytes());

        assertThatThrownBy(() -> uploadFile(file))
                .isInstanceOf(runtimeException("com.craft.userservice.file.exception.FileStorageException"))
                .hasMessage("File content type is not supported.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenContentTypeIsMissing_fails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "photo.png",
                null,
                "image bytes".getBytes());

        assertThatThrownBy(() -> uploadFile(file))
                .isInstanceOf(runtimeException("com.craft.userservice.file.exception.FileStorageException"))
                .hasMessage("File content type is required.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void uploadFile_whenValid_callsS3PutObject() throws Throwable {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        whenSaveReturnsFirstArgument();

        uploadFile(file);

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
    void uploadFile_whenValid_savesFileMetadata() throws Throwable {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        whenSaveReturnsFirstArgument();

        uploadFile(file);

        ArgumentCaptor<Object> metadataCaptor = ArgumentCaptor.forClass(Object.class);
        verifySave(metadataCaptor);

        Object metadata = metadataCaptor.getValue();
        assertThat(get(metadata, "getUploadedByUserId")).isEqualTo(USER_ID);
        assertThat(get(metadata, "getOriginalFilename")).isEqualTo("photo.png");
        assertThat(get(metadata, "getContentType")).isEqualTo("image/png");
        assertThat(get(metadata, "getSize")).isEqualTo(file.getSize());
        assertThat(get(metadata, "getBucket")).isEqualTo(BUCKET);
        assertThat(get(metadata, "getS3Key").toString()).startsWith("users/user-123/uploads/");
        assertThat(get(metadata, "getPublicUrl")).isNull();
        assertThat(get(metadata, "getVisibility").toString()).isEqualTo("PRIVATE");
        assertThat(get(metadata, "getUsageType").toString()).isEqualTo("DOCUMENT");
        assertThat(get(metadata, "getStatus").toString()).isEqualTo("UPLOADED");
        assertThat(get(metadata, "getCreatedAt")).isNotNull();
        assertThat(get(metadata, "getUpdatedAt")).isNotNull();
    }

    @Test
    void uploadFile_whenValid_returnsResponseDto() throws Throwable {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        whenSaveSetsIdAndReturnsMetadata("file-123");

        Object response = uploadFile(file);

        assertThat(get(response, "getId")).isEqualTo("file-123");
        assertThat(get(response, "getUploadedByUserId")).isEqualTo(USER_ID);
        assertThat(get(response, "getOriginalFilename")).isEqualTo("photo.png");
        assertThat(get(response, "getContentType")).isEqualTo("image/png");
        assertThat(get(response, "getSize")).isEqualTo(file.getSize());
        assertThat(get(response, "getBucket")).isEqualTo(BUCKET);
        assertThat(get(response, "getS3Key").toString()).startsWith("users/user-123/uploads/");
        assertThat(get(response, "getPublicUrl")).isNull();
        assertThat(get(response, "getVisibility").toString()).isEqualTo("PRIVATE");
        assertThat(get(response, "getUsageType").toString()).isEqualTo("DOCUMENT");
        assertThat(get(response, "getStatus").toString()).isEqualTo("UPLOADED");
        assertThat(get(response, "getCreatedAt")).isNotNull();
        assertThat(get(response, "getUpdatedAt")).isNotNull();
    }

    @Test
    void uploadAvatar_whenValid_usesPublicAvatarKeyAndUrl() throws Throwable {
        MockMultipartFile file = validFile();
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        whenSaveSetsIdAndReturnsMetadata("avatar-file-123");

        Object response = uploadAvatar(file);

        assertThat(get(response, "getId")).isEqualTo("avatar-file-123");
        assertThat(get(response, "getUploadedByUserId")).isEqualTo(USER_ID);
        assertThat(get(response, "getS3Key").toString()).startsWith("public/users/user-123/avatar/");
        assertThat(get(response, "getPublicUrl")).isEqualTo(PUBLIC_BASE_URL + "/" + get(response, "getS3Key"));
        assertThat(get(response, "getVisibility").toString()).isEqualTo("PUBLIC");
        assertThat(get(response, "getUsageType").toString()).isEqualTo("AVATAR");
    }

    @Test
    void uploadAvatar_whenFileIsSvg_succeeds() throws Throwable {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "profile.svg",
                "image/svg+xml",
                "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".getBytes());
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());
        whenSaveSetsIdAndReturnsMetadata("avatar-svg-123");

        Object response = uploadAvatar(file);

        assertThat(get(response, "getId")).isEqualTo("avatar-svg-123");
        assertThat(get(response, "getOriginalFilename")).isEqualTo("profile.svg");
        assertThat(get(response, "getContentType")).isEqualTo("image/svg+xml");
        assertThat(get(response, "getS3Key").toString()).startsWith("public/users/user-123/avatar/");
        assertThat(get(response, "getS3Key").toString()).endsWith("-profile.svg");
    }

    @Test
    void uploadAvatar_whenFileIsPdf_fails() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "profile.pdf",
                "application/pdf",
                "pdf bytes".getBytes());

        assertThatThrownBy(() -> uploadAvatar(file))
                .isInstanceOf(runtimeException("com.craft.userservice.file.exception.FileStorageException"))
                .hasMessage("File content type is not supported.");

        verifyNoInteractions(s3Client, fileMetadataRepository);
    }

    @Test
    void deleteFile_whenMetadataIsValid_callsS3DeleteObject() throws Throwable {
        Object metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        deleteFile(metadata);

        ArgumentCaptor<DeleteObjectRequest> requestCaptor = ArgumentCaptor.forClass(DeleteObjectRequest.class);
        verify(s3Client).deleteObject(requestCaptor.capture());

        DeleteObjectRequest request = requestCaptor.getValue();
        assertThat(request.bucket()).isEqualTo(BUCKET);
        assertThat(request.key()).isEqualTo("users/user-123/uploads/2026/06/file-photo.png");
    }

    @Test
    void deleteFile_whenMetadataIsValid_marksMetadataAsDeleted() throws Throwable {
        Object metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        deleteFile(metadata);

        assertThat(get(metadata, "getStatus").toString()).isEqualTo("DELETED");
        assertThat(get(metadata, "getUpdatedAt")).isNotNull();
    }

    @Test
    void deleteFile_whenMetadataIsValid_savesUpdatedMetadata() throws Throwable {
        Object metadata = storedMetadata();
        when(s3Client.deleteObject(any(DeleteObjectRequest.class)))
                .thenReturn(DeleteObjectResponse.builder().build());

        deleteFile(metadata);

        ArgumentCaptor<Object> metadataCaptor = ArgumentCaptor.forClass(Object.class);
        verifySave(metadataCaptor);
        assertThat(metadataCaptor.getValue()).isSameAs(metadata);
        assertThat(get(metadataCaptor.getValue(), "getStatus").toString()).isEqualTo("DELETED");
    }

    private Object uploadFile(MultipartFile file) throws Throwable {
        return invokeService("uploadFile", new Class<?>[] { MultipartFile.class, String.class }, file, USER_ID);
    }

    private Object uploadAvatar(MultipartFile file) throws Throwable {
        return invokeService("uploadAvatar", new Class<?>[] { MultipartFile.class, String.class }, file, USER_ID);
    }

    private void deleteFile(Object metadata) throws Throwable {
        invokeService("deleteFile", new Class<?>[] { type("com.craft.userservice.file.model.FileMetadata") }, metadata);
    }

    private Object invokeService(String methodName, Class<?>[] parameterTypes, Object... args) throws Throwable {
        try {
            Method method = service.getClass().getMethod(methodName, parameterTypes);
            return method.invoke(service, args);
        } catch (InvocationTargetException ex) {
            throw ex.getTargetException();
        }
    }

    private void whenSaveReturnsFirstArgument() throws Exception {
        when(repositorySave(any(type("com.craft.userservice.file.model.FileMetadata"))))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void whenSaveSetsIdAndReturnsMetadata(String id) throws Exception {
        when(repositorySave(any(type("com.craft.userservice.file.model.FileMetadata"))))
                .thenAnswer(invocation -> {
                    Object metadata = invocation.getArgument(0);
                    invoke(metadata, "setId", String.class, id);
                    return metadata;
                });
    }

    private Object repositorySave(Object metadata) throws Exception {
        return type("com.craft.userservice.file.repository.FileMetadataRepository")
                .getMethod("save", Object.class)
                .invoke(fileMetadataRepository, metadata);
    }

    private void verifySave(ArgumentCaptor<Object> metadataCaptor) throws Exception {
        type("com.craft.userservice.file.repository.FileMetadataRepository")
                .getMethod("save", Object.class)
                .invoke(verify(fileMetadataRepository), metadataCaptor.capture());
    }

    private MockMultipartFile validFile() {
        return new MockMultipartFile(
                "file",
                "photo.png",
                "image/png",
                "image bytes".getBytes());
    }

    private Object storedMetadata() throws Exception {
        Object metadata = newInstance("com.craft.userservice.file.model.FileMetadata");
        invoke(metadata, "setId", String.class, "file-123");
        invoke(metadata, "setUploadedByUserId", String.class, USER_ID);
        invoke(metadata, "setOriginalFilename", String.class, "photo.png");
        invoke(metadata, "setContentType", String.class, "image/png");
        invoke(metadata, "setSize", Long.class, 11L);
        invoke(metadata, "setBucket", String.class, BUCKET);
        invoke(metadata, "setS3Key", String.class, "users/user-123/uploads/2026/06/file-photo.png");
        invoke(metadata, "setStatus", type("com.craft.userservice.file.enums.FileStorageStatus"), status("UPLOADED"));
        return metadata;
    }

    private Object status(String name) throws Exception {
        return Enum.valueOf(enumType("com.craft.userservice.file.enums.FileStorageStatus"), name);
    }

    private Object get(Object target, String methodName) throws Exception {
        return target.getClass().getMethod(methodName).invoke(target);
    }

    private void invoke(Object target, String methodName, Class<?> parameterType, Object value) throws Exception {
        target.getClass().getMethod(methodName, parameterType).invoke(target, value);
    }

    private Object newInstance(String className) throws Exception {
        return type(className).getConstructor().newInstance();
    }

    private Class<?> type(String className) throws ClassNotFoundException {
        return Class.forName(className);
    }

    @SuppressWarnings("unchecked")
    private Class<? extends RuntimeException> runtimeException(String className) throws ClassNotFoundException {
        return (Class<? extends RuntimeException>) type(className);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private Class<? extends Enum> enumType(String className) throws ClassNotFoundException {
        return (Class<? extends Enum>) type(className);
    }
}
