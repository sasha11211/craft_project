package com.craft.userservice.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AddressDto {
	@NotBlank
	String city;
}
