package com.craft.userservice.user.dto.response;

import java.time.Instant;
import java.util.Set;

import com.craft.userservice.configuration.enums.Gender;
import com.craft.userservice.configuration.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {
	private String id;
	private String email;
	private String firstName;
	private String lastName;
	private Gender gender;
	private String mobile;
	private String avatarUrl;
	private Set<Role> roles;
	private Instant createdAt;
	private Instant updatedAt;
//	private String accessToken;
//	private String refreshToken;

}
