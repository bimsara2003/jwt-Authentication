package com.jwtauth.config;

import com.jwtauth.util.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException { // NOSONAR: This method signature is required by Spring Security
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.debug("No JWT token found in request headers or token does not start with Bearer. Proceeding without authentication.");
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(BEARER_PREFIX.length());
        log.debug("Extracted JWT: {}", jwt);

        try {
            username = jwtService.extractUsername(jwt);
            log.debug("Extracted username from JWT: {}", username);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Removed 'this'
                log.debug("Loaded UserDetails for username: {}", username);

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("User '{}' authenticated successfully.", username);
                } else {
                    log.warn("JWT token for user '{}' is invalid.", username);
                }
            } else if (username == null) {
                log.warn("Username could not be extracted from JWT.");
            } else { // SecurityContextHolder.getContext().getAuthentication() != null
                log.debug("User already authenticated in SecurityContext. Skipping JWT processing.");
            }
        } catch (Exception e) { // Catch generic exception for now, can be more specific (e.g., JwtException, UsernameNotFoundException)
            log.error("Error processing JWT token: {}: {}", e.getClass().getSimpleName(), e.getMessage());
        }
        filterChain.doFilter(request, response);
    }
}
