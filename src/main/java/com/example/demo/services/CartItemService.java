package com.example.demo.services;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.demo.entities.CartItem;
import com.example.demo.entities.Product;
import com.example.demo.entities.ProductImage;
import com.example.demo.entities.User;
import com.example.demo.repositories.CartItemRepository;
import com.example.demo.repositories.ProductImageRepository;
import com.example.demo.repositories.ProductRepository;
import com.example.demo.repositories.UserRepository;

@Service
public class CartItemService {
	
	CartItemRepository cartItemRepository;
	UserRepository userRepository;
	ProductRepository productRepository;
	ProductImageRepository productImageRepository;
	
	public CartItemService(CartItemRepository cartItemRepository, UserRepository userRepository, ProductRepository productRepository, ProductImageRepository productImageRepository) {
		this.cartItemRepository = cartItemRepository;
		this.userRepository = userRepository;
		this.productRepository = productRepository;
		this.productImageRepository = productImageRepository;
	}
	
	// Count Service
	public int getCartItemCount(int user_id) {
		return cartItemRepository.countTotalItems(user_id);
	}
	
    // Fetch all cart items for the user
	public Map<String, Object> getCartItems(int user_id) {
        // Fetch the cart items for the user with product details
        List<CartItem> cartItems = cartItemRepository.findCartItemsWithProductDetails(user_id);

        // Create a response map to hold the cart details
        Map<String, Object> response = new HashMap<>();

        // Fetch the user details
        User user = userRepository.findById(user_id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        response.put("username", user.getUsername());
        response.put("role", user.getRole().toString());

        // List to hold the product details
        List<Map<String, Object>> products = new ArrayList<>();
        int overallTotalPrice = 0;

        for (CartItem cartItem : cartItems) {
            Map<String, Object> productDetails = new HashMap<>();

            // Get product details
            Product product = cartItem.getProduct();

            // Fetch product images from the ProductImageRepository
            List<ProductImage> productImages = productImageRepository.findByProduct_ProductId(product.getProductId());
            String imageUrl = null;

            if (productImages != null && !productImages.isEmpty()) {
                // If there are images, get the first image's URL
                imageUrl = productImages.get(0).getImageUrl();
            } else {
                // Set a default image if no images are available
                imageUrl = "default-image-url"; // Replace this with your default image URL
            }

            // Populate product details into the map
            productDetails.put("product_id", product.getProductId());
            productDetails.put("image_url", imageUrl);
            productDetails.put("name", product.getName());
            productDetails.put("description", product.getDescription());
            productDetails.put("price_per_unit", product.getPrice());
            productDetails.put("quantity", cartItem.getQuantity());
            productDetails.put("total_price", cartItem.getQuantity() * product.getPrice().doubleValue());

            // Add the product details to the products list
            products.add(productDetails);

            // Add to the overall total price
            overallTotalPrice += cartItem.getQuantity() * product.getPrice().doubleValue();
        }

        // Prepare the final cart response
        Map<String, Object> cart = new HashMap<>();
        cart.put("products", products);
        cart.put("overall_total_price", overallTotalPrice);

        // Add the cart details to the response
        response.put("cart", cart);

        return response;
    }
	
	// Add an item to the cart 
	 public void addToCart(int user_id, int productId, int quantity) {
	        // Check if the user exists
	        User user = userRepository.findById(user_id)
	                .orElseThrow(() -> new RuntimeException("User not found"));

	        // Check if the product exists
	        Product product = productRepository.findById(productId)
	                .orElseThrow(() -> new RuntimeException("Product not found"));

	        // Check if the item is already in the cart
	        Optional<CartItem> existingCartItem = cartItemRepository.findByUserAndProduct(user_id, productId);

	        if (existingCartItem.isPresent()) {
	            // Update the quantity if the item exists
	            CartItem cartItem = existingCartItem.get();
	            cartItem.setQuantity(cartItem.getQuantity() + quantity);
	            cartItemRepository.save(cartItem);
	        } else {
	            // Create a new cart item if it doesn't exist
	            CartItem newCartItem = new CartItem(user, product, quantity);
	            cartItemRepository.save(newCartItem);
	        }
	    }
	 
	// Update Cart Item Quantity
	 public void updateCartItemQuantity(int user_id, int productId, int quantity) {
	     userRepository.findById(user_id)
	             .orElseThrow(() -> new IllegalArgumentException("User not found"));
	     productRepository.findById(productId)
	             .orElseThrow(() -> new IllegalArgumentException("Product not found"));

	     // Fetch cart item for this userId and productId
	     Optional<CartItem> existingItem = cartItemRepository.findByUserAndProduct(user_id, productId);

	     if (existingItem.isPresent()) {
	         CartItem cartItem = existingItem.get();

	         if (quantity == 0) {
	             deleteCartItem(user_id, productId);
	         } else {
	             cartItem.setQuantity(quantity);
	             cartItemRepository.save(cartItem);
	         }
	     }
	 }
	 
	// Delete Cart Item
	 public void deleteCartItem(int user_id, int productId) {
		 userRepository.findById(user_id)
	             .orElseThrow(() -> new IllegalArgumentException("User not found"));
	     productRepository.findById(productId)
	             .orElseThrow(() -> new IllegalArgumentException("Product not found"));

	     cartItemRepository.deleteCartItem(user_id, productId);
	 }
}
