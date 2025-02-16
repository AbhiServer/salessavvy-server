package com.example.demo.controllers;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.entities.User;
import com.example.demo.repositories.ProductImageRepository;
import com.example.demo.repositories.UserRepository;
import com.example.demo.services.CartItemService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/cart")
@CrossOrigin(origins = "https://salessavvyabhi.vercel.app/", allowCredentials = "true")
public class CartController {
	
	UserRepository userRepository;
	CartItemService cartItemService;
	ProductImageRepository productImageRepository;
	
	public CartController(UserRepository userRepository, CartItemService cartItemService, ProductImageRepository productImageRepository) {
		this.userRepository = userRepository;
		this.cartItemService = cartItemService;
		this.productImageRepository = productImageRepository;
		
	}
	
	// TO get the count of items
    @GetMapping("/items/count")
    public ResponseEntity<Integer> getCartItemCount(@RequestParam String username) {
    	int count = 0;
    	Optional<User> opuser = userRepository.findByUsername(username);
    	if (opuser != null) {
            User user = opuser.get();
            count = cartItemService.getCartItemCount(user.getUser_id());
            return ResponseEntity.ok(count);
    	}  else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
    
    // To get all items
    @GetMapping("/items")
    public ResponseEntity<Map<String, Object>> getCartItems(HttpServletRequest request) {
        try {
            // Fetch user by username to get the userId
            User user = (User) request.getAttribute("authenticatedUser");

            if (user == null) {
                throw new IllegalArgumentException("User not found or not authenticated");
            }

            // Call the service to get cart items for the user
            Map<String, Object> cartItems = cartItemService.getCartItems(user.getUser_id());

            // Return the cart items with a 200 OK response
            return ResponseEntity.ok(cartItems);
        } catch (IllegalArgumentException e) {
            // Handle cases where the user is not found or invalid input is provided
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            // Handle any other unexpected errors
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "An unexpected error occurred"));
        }
    }
	
    // Add an item to the cart 
    @PostMapping("/add")
    public ResponseEntity<Void> addToCart(@RequestBody Map<String, Object> request) {
        try {
            // Extract username, productId, and optional quantity from the request
            String username = (String) request.get("username");
            int productId = ((Number) request.get("productId")).intValue(); // Handle numeric types safely
            int quantity = request.containsKey("quantity") ? ((Number) request.get("quantity")).intValue() : 1;

            // Fetch the user using the username
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));

            // Add the product to the cart
            cartItemService.addToCart(user.getUser_id(), productId, quantity);

            // Return a 201 Created response for successful addition
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (IllegalArgumentException e) {
            // Handle cases where the user is not found or invalid input is provided
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (ClassCastException e) {
            // Handle cases where the request data is of an unexpected type
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            // Handle any other unexpected errors
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
	
    // Update Cart Item
    @PutMapping("/update")
    public ResponseEntity<Void> updateCartItemQuantity(@RequestBody Map<String, Object> request) {
        try {
            // Extract username, productId, and quantity from the request
            String username = (String) request.get("username");
            int productId = ((Number) request.get("productId")).intValue(); // Handle numeric types safely
            int quantity = ((Number) request.get("quantity")).intValue();

            // Fetch the user using username
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));

            // Update the cart item quantity
            cartItemService.updateCartItemQuantity(user.getUser_id(), productId, quantity);

            // Return a 200 OK response for successful update
            return ResponseEntity.status(HttpStatus.OK).build();
        } catch (IllegalArgumentException e) {
            // Handle cases where the user is not found or invalid input is provided
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (ClassCastException e) {
            // Handle cases where the request data is of an unexpected type
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception e) {
            // Handle any other unexpected errors
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    // Delete Cart Item
    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteCartItem(@RequestBody Map<String, Object> request) {
        String username = (String) request.get("username");
        int productId = (int) request.get("productId");

        // Fetch the user using username
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + username));

        // Delete the cart item
        cartItemService.deleteCartItem(user.getUser_id(), productId);

        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
