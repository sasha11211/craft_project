package com.craft.userservice.user;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.configuration.enums.Role;
import com.craft.userservice.jwt.RefreshTokenService;
import com.craft.userservice.jwt.dto.RefreshRequestDto;
import com.craft.userservice.jwt.model.RefreshToken;
import com.craft.userservice.security.JwtUtil;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;
import com.craft.userservice.user.dto.UpdateUserDto;
import com.craft.userservice.user.dto.response.AuthResponseDto;
import com.craft.userservice.user.dto.response.UserResponseDto;
import com.craft.userservice.user.model.User;
import com.craft.userservice.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;
	private final RefreshTokenService refreshTokenService;
	private final ModelMapper modelMapper;
	
	@Override
	public ResponseEntity<?> register(RegisterRequestDto registerRequestDto) {
		if (userRepository.existsByEmail(registerRequestDto.getEmail())) {
			return ResponseEntity.badRequest().body("Email already in use");
		}
		User user = User.builder().email(registerRequestDto.getEmail()).password(passwordEncoder.encode(registerRequestDto.getPassword()))
				.roles(new HashSet<>(Set.of(Role.ROLE_CUSTOMER))).createdAt(Instant.now()).updatedAt(Instant.now())
				.build();
		userRepository.save(user);
		String accessToken = jwtUtil.generateToken(user.getEmail());
		String refreshToken = refreshTokenService.create(user.getId()).getToken();
		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
		userResponseDto.setAccessToken(accessToken);
		userResponseDto.setRefreshToken(refreshToken);
		return ResponseEntity.ok(userResponseDto);
	}
	
	@Override
	public ResponseEntity<?> login(LoginRequestDto loginRequestDto) {
		User user = userRepository.findByEmail(loginRequestDto.getEmail()).orElse(null);
		if (user == null || !passwordEncoder.matches(loginRequestDto.getPassword(), user.getPassword())) {
			return ResponseEntity.badRequest().body("Invalid email or password");
		}

		String accessToken = jwtUtil.generateToken(user.getEmail());
		String refreshToken = refreshTokenService.create(user.getId()).getToken();

		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
		userResponseDto.setAccessToken(accessToken);
		userResponseDto.setRefreshToken(refreshToken);
		return ResponseEntity.ok(userResponseDto);

	}
	
	// ротація refresh + новий access
	@Override
	public ResponseEntity<?> refreshToken(RefreshRequestDto refreshRequestDto) {
		try {
			RefreshToken newRefresh = refreshTokenService.rotate(refreshRequestDto.getRefreshToken());

			User user = userRepository.findById(newRefresh.getUserId())
					.orElseThrow(() -> new RuntimeException("User not found"));

			String newAccessToken = jwtUtil.generateToken(user.getEmail());
			return ResponseEntity.ok(new AuthResponseDto(newAccessToken, newRefresh.getToken()));

		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Invalid or expired refresh token");
		}

	}
	
	@Override
	public ResponseEntity<?> logout(RefreshRequestDto refreshRequestDto, Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeByToken(refreshRequestDto.getRefreshToken(), user.getId());
		return ResponseEntity.ok("Logged out from current device");
	}
	
	@Override
	public ResponseEntity<?> logoutAll(Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeAllByUserId(user.getId());
		return ResponseEntity.ok("Logged out from all devices");
	}

	@Override
	public ResponseEntity<?> getCurrentUser(Authentication authentication) {
		 if (authentication == null || authentication.getPrincipal() == null) {
	            return ResponseEntity.status(401).body("Unauthorized");
	        }
	        String email = (String) authentication.getPrincipal();

	        User user = userRepository.findByEmail(email).orElse(null);
	        if (user == null) {
	            return ResponseEntity.status(404).body("User not found");
	        }
	        UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
	        //токени тут не повертаємо 
	        userResponseDto.setAccessToken(null);
	        userResponseDto.setRefreshToken(null);
	        return ResponseEntity.ok(userResponseDto);
	}

	@Override
	public ResponseEntity<?> updateUser(UpdateUserDto updateUserDto, Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        String email = (String) authentication.getPrincipal();

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body("User not found");
        }

        // Перевірка, що мобільний не зайнятий іншим користувачем
        if (updateUserDto.getMobile() != null && !updateUserDto.getMobile().isBlank()) {
            userRepository.findByMobile(updateUserDto.getMobile())
                    .filter(other -> !other.getId().equals(user.getId()))
                    .ifPresent(other -> { throw new IllegalArgumentException("Mobile already in use"); });
        }
        
        // Мапимо тільки не-null поля з DTO
        modelMapper.map(updateUserDto, user);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
        userResponseDto.setAccessToken(null);
        userResponseDto.setRefreshToken(null);
        return ResponseEntity.ok(updateUserDto);
	}

}
