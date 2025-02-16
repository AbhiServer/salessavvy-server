package com.example.demo.repositories;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.demo.entities.JwtToken;
import com.example.demo.entities.User;

import jakarta.transaction.Transactional;

@Repository
public interface AuthRepository extends JpaRepository<JwtToken, Integer> {

    Optional<JwtToken> findByToken(String token);

    List<JwtToken> findAllByUser(User user);

    void deleteByToken(String token);

    @Query("SELECT t FROM JwtToken t WHERE t.user.user_id = :userId AND t.expiresAt > :now")
    List<JwtToken> findValidTokensByUser(@Param("userId") int userId, @Param("now") LocalDateTime now);

    // Custom query to delete tokens by user ID 
    @Modifying 
    @Transactional 
    @Query("DELETE FROM JwtToken t WHERE t.user.user_id = :userId") 
    void deleteByUserId(@Param("userId") int userId);

    // Custom query to delete expired tokens
    @Modifying
    @Transactional
    @Query("DELETE FROM JwtToken t WHERE t.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
}
