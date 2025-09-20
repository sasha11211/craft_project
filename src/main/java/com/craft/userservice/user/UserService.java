package com.craft.userservice.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import com.craft.userservice.jwt.dto.RefreshRequestDto;
import com.craft.userservice.user.dto.AddRoleDto;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;
import com.craft.userservice.user.dto.UpdateUserDto;

public interface UserService {
	public ResponseEntity<?> register(RegisterRequestDto registerRequestDto);
	
	public ResponseEntity<?> login(LoginRequestDto loginRequestDto);
	
	public ResponseEntity<?> refreshToken(String oldRefresh);
	
	public ResponseEntity<?> logout(RefreshRequestDto refreshRequestDto, Authentication authentication);
	
	public ResponseEntity<?> logoutAll(Authentication authentication);
	
	public ResponseEntity<?> getCurrentUser(Authentication authentication);
	
	public ResponseEntity<?> updateUser(UpdateUserDto updateUserDto, Authentication authentication);
	
	public ResponseEntity<?> addRole(AddRoleDto addRoleDto, Authentication authentication);
	

}
