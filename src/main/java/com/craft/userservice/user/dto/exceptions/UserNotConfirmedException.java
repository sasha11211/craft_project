package com.craft.userservice.user.dto.exceptions;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserNotConfirmedException extends RuntimeException{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public UserNotConfirmedException(String email) {
        super("User with email : " + email + " is not confirmed");
    }

}
