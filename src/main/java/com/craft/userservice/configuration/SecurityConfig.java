package com.craft.userservice.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.craft.userservice.security.JwtCookieAuthFilter;

@Configuration
public class SecurityConfig {
	private final JwtCookieAuthFilter cookieAuthFilter;

	public SecurityConfig(JwtCookieAuthFilter cookieAuthFilter) {
		this.cookieAuthFilter = cookieAuthFilter;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(
						reg -> reg.requestMatchers("/api/user/auth/register", "/api/user/auth/login", "/api/user/auth/refresh")
								.permitAll().anyRequest().authenticated())
				.httpBasic(Customizer.withDefaults());

		http.addFilterBefore(cookieAuthFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

}
