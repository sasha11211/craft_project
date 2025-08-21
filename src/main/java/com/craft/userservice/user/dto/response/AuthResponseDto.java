package com.craft.userservice.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponseDto {
	private String accessToken;
	private String refreshToken;

}
