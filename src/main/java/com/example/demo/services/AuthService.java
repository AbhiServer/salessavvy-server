package com.example.demo.services;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.dtos.LoginDto;
import com.example.demo.entities.JwtToken;
import com.example.demo.entities.User;
import com.example.demo.repositories.AuthRepository;
import com.example.demo.repositories.UserRepository;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.transaction.Transactional;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Service
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final AuthRepository authRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final SecretKey jwtKey;
    private final long jwtExpirationMs;

    public AuthService(
            UserRepository userRepository,
            AuthRepository authRepository,
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.expiration}") long jwtExpirationMs) {
        this.userRepository = userRepository;
        this.authRepository = authRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
        this.jwtKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public Map<String, Object> authenticate(LoginDto loginDto) {
    	User user = userRepository.findByUsername(loginDto.getUsername())
    	        .orElseThrow(() -> new RuntimeException("User not found"));
    	if (!passwordEncoder.matches(loginDto.getPassword(), user.getPassword())) {
    	    throw new RuntimeException("Invalid password");
        }
    	String token = generateToken(user);
    	saveUserToken(user, token);
    	Map<String, Object> response = new HashMap<>();
    	response.put("token", token);
    	response.put("username", user.getUsername());
    	response.put("role", user.getRole());
    	return response;
    }
    private String generateToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);
        String token = Jwts.builder()
                .setSubject(Integer.toString(user.getUser_id()))
                .claim("username", user.getUsername())
                .claim("role", user.getRole().name())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(jwtKey)
                .compact();
        return token;
    }

    private void saveUserToken(User user, String token) {
        JwtToken jwtToken = new JwtToken();
        jwtToken.setUser(user);
        jwtToken.setToken(token);
        // Set expiration based on jwtExpirationMs (converted from ms to seconds)
        jwtToken.setExpiresAt(LocalDateTime.now().plusSeconds(jwtExpirationMs / 1000));
        authRepository.save(jwtToken);
    }

    public void logout(String token) {
        authRepository.deleteByToken(token);
    }

    public boolean validateToken(String token) {
        try {
            System.err.println("VALIDATING TOKEN...");
            // Parse and validate the token
            Jwts.parserBuilder()
                    .setSigningKey(jwtKey) // Use your signing key here
                    .build()
                    .parseClaimsJws(token); // This will throw an exception if the token is invalid

            // Check if the token exists in the database
            Optional<JwtToken> jwtToken = authRepository.findByToken(token);
            if (jwtToken.isPresent()) {
                // Check if the token is not expired
                return jwtToken.get().getExpiresAt().isAfter(LocalDateTime.now());
            }
            return false;

        } catch (ExpiredJwtException e) {
            // When token is expired, delete it from the database
            authRepository.deleteByToken(token);
            return false;

        } catch (Exception e) {
            // Handle other exceptions
            return false;
        }
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("username", String.class); // Extract username from custom claim
    }
}