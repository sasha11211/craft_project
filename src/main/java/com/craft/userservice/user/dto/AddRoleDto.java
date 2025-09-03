package com.craft.userservice.user.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class AddRoleDto {
	@NotNull
	private String role;

}
