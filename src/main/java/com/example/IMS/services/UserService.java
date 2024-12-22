package com.example.IMS.services;
import java.util.List;

import com.example.IMS.entities.*;
public interface UserService {
	public boolean registerUser(User user);
	public User loginUser(String email,String password , String role);
	public List<User> getAllUser();
}
