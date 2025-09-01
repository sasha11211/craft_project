package com.craft.userservice.user.dto.exceptions;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class UserNotFoundExceptionById extends RuntimeException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public UserNotFoundExceptionById(String id) {
        super("User with id : " + id + " Not found");
    }
}
