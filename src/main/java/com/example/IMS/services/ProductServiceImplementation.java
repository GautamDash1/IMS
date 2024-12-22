package com.example.IMS.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.IMS.entities.Product;
import com.example.IMS.repositories.ProductRepository;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductServiceImplementation implements ProductService {

    @Autowired
    private ProductRepository productRepository;

    @Override
    public List<String> getAllCategories() {
        return productRepository.findAllCategories();
    }
    
    @Override
    public List<String> getProductNamesByCategory(String category) {
        if ("all".equalsIgnoreCase(category) || category == null) {
            return productRepository.findAllProductNames();
        } else {
            return productRepository.findProductNamesByCategory(category);
        }
    }

    @Override
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @Override
    public Product addProduct(Product product) {
        return productRepository.save(product);
    }
    @Override
    public Double getPriceByProductName(String productName) {
    	Double price = productRepository.findpriceByproductName(productName);
        return (price != null) ? price : 0.0; // Return 0.0 if price is null
    }
    @Override
    public Product updateProduct(Long id, Product productDetails) {
        Product existingProduct = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found"));
        existingProduct.setProductName(productDetails.getProductName());
        existingProduct.setCategory(productDetails.getCategory());
        existingProduct.setPrice(productDetails.getPrice());
        existingProduct.setStock(productDetails.getStock());
        return productRepository.save(existingProduct);
    }
    @Override
    public List<Product>getProductsByCategory(String category){
    	return productRepository.findByCategory(category);
    }
    @Override
    public void deleteProduct(Long id) {
        if (!productRepository.existsById(id)) {
            throw new RuntimeException("Product not found");
        }
        productRepository.deleteById(id);
    }
    
    @Override
    public Product getProductById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
    }
    
    
    
}
