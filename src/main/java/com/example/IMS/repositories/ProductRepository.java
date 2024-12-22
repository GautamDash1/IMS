package com.example.IMS.repositories;

import com.example.IMS.entities.Product;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
    // Custom queries can be added here if needed
	 // Get all distinct categories
    @Query("SELECT DISTINCT p.category FROM Product p")
    List<String> findAllCategories();
    
 // Fetch product names by category
    @Query("SELECT p.productName FROM Product p WHERE p.category = :category")
    List<String> findProductNamesByCategory(@Param("category") String category);
 // Fetch all product names
    @Query("SELECT p.productName FROM Product p")
    List<String> findAllProductNames();
    // Get products by category
    List<Product> findByCategory(String category);
    
    @Query("SELECT p.price FROM Product p WHERE p.productName = :productName")
    Double findpriceByproductName(String productName);
}
