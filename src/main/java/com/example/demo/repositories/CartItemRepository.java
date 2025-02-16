package com.example.demo.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.example.demo.entities.CartItem;

import jakarta.transaction.Transactional;

@Repository
public interface CartItemRepository extends JpaRepository<CartItem, Integer>{
	
	// Count the total quantity of items in the cart
	@Query("SELECT COALESCE(SUM(c.quantity), 0) FROM CartItem c WHERE c.user.user_id = :user_id") 
	int countTotalItems(int user_id);
	
	// Fetch cart item for a given userId and productId 
	@Query("SELECT c FROM CartItem c WHERE c.user.user_id = :user_id AND c.product.productId = :productId") 
	Optional<CartItem> findByUserAndProduct(int user_id, int productId);
	
	@Query("SELECT c FROM CartItem c JOIN FETCH c.product p LEFT JOIN FETCH ProductImage pi ON p.productId = pi.product.productId WHERE c.user.user_id = :user_id") 
	List<CartItem> findCartItemsWithProductDetails(int user_id);
	
	// Update quantity for a specific cart item 
	@Query("UPDATE CartItem c SET c.quantity = :quantity WHERE c.id = :cartItemId") 
	void updateCartItemQuantity(int cartItemId, int quantity);
	
	// Delete a product from the cart 
	@Modifying 
	@Transactional 
	@Query("DELETE FROM CartItem c WHERE c.user.user_id = :user_id AND c.product.productId = :productId") 
	void deleteCartItem(int user_id, int productId);
	
	@Modifying
	@Transactional 
	@Query("DELETE FROM CartItem c WHERE c.user.user_id = :user_id") 
	void deleteAllCartItemsByUserId(int user_id);

}
