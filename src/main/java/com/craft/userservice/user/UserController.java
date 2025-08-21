package com.craft.userservice.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.craft.userservice.jwt.dto.RefreshRequestDto;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;
import com.craft.userservice.user.dto.UpdateUserDto;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
	private final UserServiceImpl userService;

	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody RegisterRequestDto registerRequestDto) {
		return userService.register(registerRequestDto);
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequestDto loginRequestDto) {
		return userService.login(loginRequestDto);
	}

	@PostMapping("/refresh")
	public ResponseEntity<?> refresh(@RequestBody RefreshRequestDto refreshRequestDto) {
		return userService.refreshToken(refreshRequestDto);
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestBody RefreshRequestDto refreshRequestDto, Authentication authentication) {
		return userService.logout(refreshRequestDto, authentication);
	}

	@PostMapping("/logout-all")
	public ResponseEntity<?> logoutAll(Authentication authentication) {
		return userService.logoutAll(authentication);
	}

	@GetMapping("/current")
	public ResponseEntity<?> getCurrentUser(Authentication authentication) {
		return userService.getCurrentUser(authentication);
	}

	@PutMapping("/update")
	public ResponseEntity<?> updateCurrentUser(@Valid @RequestBody UpdateUserDto request,
			Authentication authentication) {
		return userService.updateUser(request, authentication);
	}

}
