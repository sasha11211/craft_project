package com.craft.userservice.user.dto;

import com.craft.userservice.configuration.enums.Gender;

import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class UpdateUserDto {
	private String firstName;           
    private String lastName;             
    private Gender gender;
    // E.164, напр. +972501234567
    @Pattern(regexp = "^\\+?[1-9]\\d{6,14}$", message = "Mobile must be in E.164 format, e.g. +972501234567")
    private String mobile;
    private String avatarUrl; 

}
