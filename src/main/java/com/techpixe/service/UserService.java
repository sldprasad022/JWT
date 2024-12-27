package com.techpixe.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.data.domain.Page;

import com.techpixe.dto.UserDto;
import com.techpixe.entity.User;

public interface UserService 
{
	User saveUser(String userName,String email,Long mobileNumber,String department,Double salary,String password);
	
	User fetchByUserId(Long userId);
	
	List<User> fetchAllUsers();
	
	//Fetch All With Sorting based on field
	public List<User> fetchAllUserswithSorting(String field);
	
	//Pagination
	public Page<User> fetchAllUsersWithPagination(int offset,int pageSize);
	
	//Pagination with Sorting 
	public Page<User> fetchAllUsersWithPaginationWithSorting(int offset,int pageSize,String field);
	
	void deleteByUserId(Long userId);
	
	Optional<User> updateUserById(Long userId,String userName,String email,Long mobileNumber,String department,Double salary);
	
	//UserDto login(String email,String password);
	
	public Map<String, Object> login(String email, String password);
	
	String forgotPasswordSendOTP(String email);
	
	String forgotPassword(String email,String newPassword, String otp);
	
	String changePassword(String oldPassword,String password,String confirmPassword,Long userProfileId);
	
	
}
