package com.example.demo.services;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.entities.User;
import com.example.demo.repositories.UserRepository;

@Service
public class UserService {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	
	public UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
		this.passwordEncoder = new BCryptPasswordEncoder();
	}
	
	public User userRegister(User user) {
		
	if(userRepository.findByUsername(user.getUsername()).isPresent()){
		throw new RuntimeException("Username already taken");
	}
	if(userRepository.findByEmail(user.getEmail()).isPresent()) {
		throw new RuntimeException("Email already registerd");
	}
	
		String pwd = user.getPassword();
		String epwd = passwordEncoder.encode(pwd);
		user.setPassword(epwd);
		return userRepository.save(user);
	}

}
