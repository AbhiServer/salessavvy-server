package com.example.demo.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.dtos.ProfileDTO;
import com.example.demo.entities.User;
import com.example.demo.repositories.UserRepository;

import jakarta.servlet.http.HttpServletRequest;

import java.time.format.DateTimeFormatter;

@Service
public class ProfileService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private HttpServletRequest request;

    public ProfileDTO getCurrentUserProfile() {
        // Get the authenticated user from the request attribute
        User authenticatedUser = (User) request.getAttribute("authenticatedUser");
        if (authenticatedUser == null) {
            throw new RuntimeException("User not authenticated");
        }
        
        // Fetch fresh user data from database
        User user = userRepository.findByUsername(authenticatedUser.getUsername())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        return convertToDTO(user);
    }

    public ProfileDTO updateProfile(ProfileDTO profileDTO) {
        // Get the authenticated user from the request attribute
        User authenticatedUser = (User) request.getAttribute("authenticatedUser");
        if (authenticatedUser == null) {
            throw new RuntimeException("User not authenticated");
        }

        // Fetch fresh user data from database
        User user = userRepository.findByUsername(authenticatedUser.getUsername())
            .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate new username if it's different
        if (!user.getUsername().equals(profileDTO.getUsername())) {
            if (userRepository.findByUsername(profileDTO.getUsername()).isPresent()) {
                throw new RuntimeException("Username already taken");
            }
            user.setUsername(profileDTO.getUsername());
        }

        // Validate new email if it's different
        if (!user.getEmail().equals(profileDTO.getEmail())) {
            if (userRepository.findByEmail(profileDTO.getEmail()).isPresent()) {
                throw new RuntimeException("Email already taken");
            }
            user.setEmail(profileDTO.getEmail());
        }

        User updatedUser = userRepository.save(user);
        return convertToDTO(updatedUser);
    }

    private ProfileDTO convertToDTO(User user) {
        ProfileDTO dto = new ProfileDTO();
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole().toString());
        dto.setCreated_at(user.getCreated_at().format(DateTimeFormatter.ISO_LOCAL_DATE));
        return dto;
    }
}
