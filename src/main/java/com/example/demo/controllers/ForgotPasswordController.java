package com.example.demo.controllers;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Random;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dtos.ChangePassword;
import com.example.demo.dtos.MailBody;
import com.example.demo.entities.ForgotPassword;
import com.example.demo.entities.User;
import com.example.demo.repositories.ForgotPasswordRepository;
import com.example.demo.repositories.UserRepository;
import com.example.demo.services.EmailService;

@RestController
@RequestMapping("/api/forgotPassword")
@CrossOrigin
public class ForgotPasswordController {
	
	private final UserRepository userRepository;
	private final EmailService emailService;
	private final ForgotPasswordRepository forgotPasswordRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	
	
	public ForgotPasswordController(UserRepository userRepository, EmailService emailService, ForgotPasswordRepository forgotPasswordRepository) {
		this.userRepository = userRepository;
		this.emailService = emailService;
		this.forgotPasswordRepository = forgotPasswordRepository;
		this.passwordEncoder = new BCryptPasswordEncoder();
	}


	// send mail for email verification
	
	@PostMapping("/verifyMail/{email}")
	public ResponseEntity<String> verifyEmail(@PathVariable String email) {
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("Please provide vaild email" + email));
		
		int otp = otpGenerator();		
		MailBody mailBody = MailBody.builder()
				.to(email)
				.text("Your verification code is: " +otp)
				.subject("OTP for Forgot Password.")
				.build();
		
		ForgotPassword fp = ForgotPassword.builder()
				.otp(otp)
				.expirationTime(new Date(System.currentTimeMillis() + 300 * 1000))
				.user(user)
				.build();
		emailService.simpleMessage(mailBody);
		forgotPasswordRepository.save(fp);
		
		return ResponseEntity.ok("OTP sent Verify Your Email");
		
	}
	
	@PostMapping("/verifyOtp/{otp}/{email}")
	public ResponseEntity<String> verifyOtp(@PathVariable Integer otp, @PathVariable String email) {
	    User user = userRepository.findByEmail(email)
	            .orElseThrow(() -> new UsernameNotFoundException("Please provide valid email"));

	    ForgotPassword fp = forgotPasswordRepository.findByOtpAndUser(otp, user)
	            .orElseThrow(() -> new RuntimeException("Invalid OTP for Email: " + email));
	    
	    // Delete existing OTP for this user
	    forgotPasswordRepository.deleteByUser(user); // Uses the custom query

	    if (fp.getExpirationTime().before(Date.from(Instant.now()))) {
	        forgotPasswordRepository.deleteById(fp.getFpid()); // Delete expired OTP
	        return new ResponseEntity<>("OTP has expired!", HttpStatus.EXPECTATION_FAILED);
	    }

	    forgotPasswordRepository.deleteById(fp.getFpid()); // Delete valid OTP after verification
	    return ResponseEntity.ok("OTP verified!");
	}
	
	@PostMapping("/changePassword/{email}")
	public ResponseEntity<String> changePasswordHandler(@RequestBody ChangePassword changePassword,@PathVariable String email) {
		
		if(!Objects.equals(changePassword.password(), changePassword.repeatPassword())) {
			return new ResponseEntity<> ("Please enter password again!", HttpStatus.EXPECTATION_FAILED);
		}
		
		String encodedPassword = passwordEncoder.encode(changePassword.password());
		userRepository.updatePassword(email, encodedPassword);
		return ResponseEntity.ok("Password has been changed!");
		
	}
	
	private Integer otpGenerator() {
		Random random = new Random();
		return random.nextInt(100_000, 999_999);
	}

}
