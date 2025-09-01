package com.craft.userservice.user.dto.exceptions;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserExistException extends RuntimeException{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public UserExistException(String email) {
        super("User with email: " + email + " already exists");
    }

}
