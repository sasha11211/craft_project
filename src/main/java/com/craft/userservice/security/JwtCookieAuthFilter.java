package com.craft.userservice.security;

import org.springframework.stereotype.Component;

import com.craft.userservice.user.model.User;
import com.craft.userservice.user.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.stream.Collectors;
import org.springframework.security.core.context.SecurityContextHolder;

@Component
@RequiredArgsConstructor
public class JwtCookieAuthFilter extends OncePerRequestFilter {
	private final JwtUtil jwtUtil;
	private final UserRepository userRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, jakarta.servlet.ServletException {

		String accessToken = null;
		if (request.getCookies() != null) {
			for (Cookie c : request.getCookies()) {
				if ("access_token".equals(c.getName())) {
					accessToken = c.getValue();
				}
			}
		}

		if (accessToken != null && jwtUtil.validateToken(accessToken)) {
			String email = jwtUtil.getEmailFromJwt(accessToken);

			User user = userRepository.findByEmail(email).orElse(null);
			if (user != null) {
				var authorities = user.getRoles().stream().map(r -> new SimpleGrantedAuthority(r.name())) // enum ROLE_*
						.collect(Collectors.toList());

				var auth = new UsernamePasswordAuthenticationToken(email, null, authorities);
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		}

		chain.doFilter(request, response);
	}
}
