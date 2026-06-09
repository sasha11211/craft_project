package com.craft.userservice.file.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FileDownloadUrlResponseDto {
    private String id;
    private String originalFilename;
    private String downloadUrl;
}
