package com.example.demo.entities;

import java.util.Date;
import jakarta.persistence.*;

@Entity
public class ForgotPassword {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer fpid;
	
	@Column(nullable = false)
	private Integer otp;
	
	@Column(nullable = false)
	private Date expirationTime;
	
	@OneToOne
	private User user;

	// Default constructor (required by JPA)
	public ForgotPassword() {
	}

	// Parameterized constructor
	public ForgotPassword(Integer fpid, Integer otp, Date expirationTime, User user) {
		this.fpid = fpid;
		this.otp = otp;
		this.expirationTime = expirationTime;
		this.user = user;
	}

	// Getters and Setters
	public Integer getFpid() {
		return fpid;
	}

	public void setFpid(Integer fpid) {
		this.fpid = fpid;
	}

	public Integer getOtp() {
		return otp;
	}

	public void setOtp(Integer otp) {
		this.otp = otp;
	}

	public Date getExpirationTime() {
		return expirationTime;
	}

	public void setExpirationTime(Date expirationTime) {
		this.expirationTime = expirationTime;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	// Custom Builder Class
	public static class ForgotPasswordBuilder {
		private Integer otp;
		private Date expirationTime;
		private User user;

		public ForgotPasswordBuilder otp(Integer otp) {
			this.otp = otp;
			return this;
		}

		public ForgotPasswordBuilder expirationTime(Date expirationTime) {
			this.expirationTime = expirationTime;
			return this;
		}

		public ForgotPasswordBuilder user(User user) {
			this.user = user;
			return this;
		}

		public ForgotPassword build() {
			return new ForgotPassword(null, otp, expirationTime, user);
		}
	}

	// Static method to get the builder instance
	public static ForgotPasswordBuilder builder() {
		return new ForgotPasswordBuilder();
	}

	// Override toString() for better debugging
	@Override
	public String toString() {
		return "ForgotPassword{" +
				"fpid=" + fpid +
				", otp=" + otp +
				", expirationTime=" + expirationTime +
				", user=" + user +
				'}';
	}
}