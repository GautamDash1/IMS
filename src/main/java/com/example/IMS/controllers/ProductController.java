package com.example.IMS.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.example.IMS.entities.Product;
import com.example.IMS.services.ProductService;

import java.util.List;

@Controller
public class ProductController {

    @Autowired
    private ProductService productService;
    // View : User Page
    @GetMapping("/userPage")
    public String openUserPage(@RequestParam(value = "category", required = false) String category, Model model) {
    	List<String> categories = productService.getAllCategories();
        List<Product> products;

        // Filter products if a category is selected
        if (category != null && !category.equals("all")) {
            products = productService.getProductsByCategory(category);
        } else {
            products = productService.getAllProducts();
        }

        model.addAttribute("categories", categories);
        model.addAttribute("products", products);
        model.addAttribute("selectedCategory", category);
        return "user";
    }
    // View: List All Products
    @GetMapping("/adminPage")
    public String getAdminPage(@RequestParam(value = "category", required = false) String category, Model model) {
        List<String> categories = productService.getAllCategories();
        List<Product> products;

        // Filter products if a category is selected
        if (category != null && !category.equals("all")) {
            products = productService.getProductsByCategory(category);
        } else {
            products = productService.getAllProducts();
        }

        model.addAttribute("categories", categories);
        model.addAttribute("products", products);
        model.addAttribute("selectedCategory", category);
        return "admin"; // Resolves to templates/admin.html
    }
    
    @GetMapping("/adminPage/addProduct")
    public String openAddProductPage(Model model) {
        model.addAttribute("product", new Product());
        return "addProduct"; // Resolves to templates/addProduct.html
    }

    // Action: Add Product
    @PostMapping("/adminPage/addProductForm")
    public String submitAddProductForm(@ModelAttribute("product") Product product, Model model) {
    	System.out.println("Product Details: " + product); // Debugging line
    	try {
            // Save the product using the ProductService
            Product savedProduct = productService.addProduct(product);

            // Add a success message to the model
            model.addAttribute("successMsg", "Product added successfully!");
            return "redirect:/adminPage"; // Redirect to the product list page
        } catch (Exception e) {
            // Handle any exceptions and add an error message
            model.addAttribute("errorMsg", "Product could not be added due to an error: " + e.getMessage());
            return "addProduct"; // Stay on the add product page
        }
    }

    @GetMapping("/adminPage/update/{id}")
    public String openUpdateProductPage(@PathVariable Long id, Model model) {
        Product product = productService.getProductById(id);
        if (product != null) {
            model.addAttribute("product", product);
            return "update"; // Resolves to templates/updateProduct.html
        } else {
            model.addAttribute("errorMsg", "Product not found!");
            return "redirect:/adminPage"; // Redirect to the product list page
        }
    }
    
    @RequestMapping(value = "/adminPage/update/{id}", method = RequestMethod.POST)
    public String updateProduct(@PathVariable(value = "id") Long id, @ModelAttribute("product") Product product, Model model) {
        try {
            // Update product logic
            productService.updateProduct(id, product);
            return "redirect:/adminPage"; // Redirect to the product list page after successful update
        } catch (RuntimeException e) {
            model.addAttribute("errorMsg", "Error updating product!");
            return "update"; // Return to the update page in case of error
        }
    }

    // Action: Delete Product
    @GetMapping("/adminPage/delete/{id}")
    public String deleteProduct(@PathVariable(value = "id") Long id) {
        try {
            productService.deleteProduct(id);
        } catch (RuntimeException e) {
            // Optional: Log error
        }
        return "redirect:/adminPage"; // Redirect to the product list page
    } 
}
