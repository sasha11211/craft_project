package com.craft.userservice.user.dto;

import lombok.Data;

@Data
public class AddressDto {
	String city;
	String street;
	String building;
	String postalCode;
}
