package com.example.IMS.services;
import com.example.IMS.entities.Product;
import java.util.List;

public interface ProductService {
    Product getProductById(Long id);
    List<Product> getAllProducts();
    Product updateProduct(Long id, Product productDetails);
    Product addProduct(Product product);
    void deleteProduct(Long id);
    List<String> getProductNamesByCategory(String category);
    List<Product>getProductsByCategory(String category);
    List<String> getAllCategories();
    Double getPriceByProductName(String productName);
	
}
