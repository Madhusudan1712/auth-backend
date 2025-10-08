package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.model.Role;
import com.authcenter.auth_backend.model.User;
import com.authcenter.auth_backend.repository.UserRepository;
import com.authcenter.auth_backend.service.EmailService;
import com.authcenter.auth_backend.service.UserService;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final EmailService emailService;

	public UserServiceImpl(UserRepository userRepository,
						  EmailService emailService) {
		this.userRepository = userRepository;
		this.emailService = emailService;
	}

	@Override
	public Optional<User> findByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	@Override
	public Optional<User> findByEmailAndApplication(String email, String application) {
		return userRepository.findByEmailAndApplication(email, application);
	}

	@Override
	public Boolean existsByEmailAndApplication(String email, String application) {
		return userRepository.existsByEmailAndApplication(email, application);
	}

	@Override
	public boolean existsByEmailRoleApplication(String email, Role role, String application) {
		return userRepository.existsByEmailAndApplicationAndRolesRole(email, application, role);
	}

	@Override
	public boolean existsByEmail(String email) {
		return userRepository.existsByEmail(email);
	}

	@Override
	public User save(User user) {
		return userRepository.save(user);
	}
}
