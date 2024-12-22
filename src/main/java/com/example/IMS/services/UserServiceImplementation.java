package com.example.IMS.services;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.IMS.entities.User;
import com.example.IMS.repositories.UserRepository;

@Service
public class UserServiceImplementation implements UserService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public boolean registerUser(User user) {
        try {
            if (user.getRole() == null || user.getRole().isEmpty()) {
                user.setRole("USER"); // Assign default role
            }
            userRepository.save(user);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public User loginUser(String email, String password , String Role) {
        User validUser = userRepository.findByEmail(email);
        if (validUser != null && validUser.getPassword().equals(password) && validUser.getRole().equals(Role)) {
            return validUser;
        }
        return null;
    }

    @Override
    public List<User> getAllUser() {
        return userRepository.findAll();
    }
}
