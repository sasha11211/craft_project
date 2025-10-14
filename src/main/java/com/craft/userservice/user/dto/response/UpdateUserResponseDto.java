package com.craft.userservice.user.dto.response;

import java.time.Instant;
import java.util.Set;

import com.craft.userservice.configuration.enums.Gender;
import com.craft.userservice.configuration.enums.Role;
import com.craft.userservice.user.dto.AddressDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserResponseDto {
	private String id;
	private String email;
	private String login;
	private String firstName;
	private String lastName;
	private Gender gender;
	private String mobile;
	private String avatarUrl;
	private Set<Role> roles;
	private Instant createdAt;
	private Instant updatedAt;
	private AddressDto address;

}
