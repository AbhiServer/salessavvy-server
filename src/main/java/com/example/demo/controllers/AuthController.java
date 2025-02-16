package com.example.demo.controllers;

import java.util.Map;


import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dtos.LoginDto;
import com.example.demo.services.AuthService;

@RestController
@RequestMapping("/api/users")
@CrossOrigin
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto) {
        try {
            Map<String, Object> response = authService.authenticate(loginDto);
            String token = (String) response.get("token");

            // Create an HTTP-only cookie with the JWT token
            ResponseCookie cookie = ResponseCookie.from("jwt", token)
                    .httpOnly(true) // Prevent JavaScript access
                    .path("/") // Available across the entire domain
                    .maxAge(3600) // Expires after 1 hour (in seconds)
                    .secure(true) // Set to true if using HTTPS
                    .sameSite("None") // Recommended for security
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(Map.of(
                            "message", "Login successful!",
                            "role", response.get("role"),
                            "username", response.get("username")
                    ));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("Error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String token) {
        try {
            if (token == null || !token.startsWith("Bearer ")) {
                return ResponseEntity.badRequest().body(Map.of("Error", "Invalid token format"));
            }

            token = token.substring(7); // Remove "Bearer " prefix
            authService.logout(token);

            // Clear the cookie by setting its maxAge to 0
            ResponseCookie cookie = ResponseCookie.from("jwt", "")
                    .httpOnly(true)
                    .path("/")
                    .maxAge(0)
                    .build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(Map.of("message", "Logged out successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("Error", e.getMessage()));
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            boolean isValid = authService.validateToken(token);
            if (isValid) {
                return ResponseEntity.ok(Map.of("valid", true));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false));
    }
}