package com.authcenter.auth_backend.service.impl;

import com.authcenter.auth_backend.model.UserRole;
import com.authcenter.auth_backend.repository.UserRoleRepository;
import com.authcenter.auth_backend.service.UserRoleService;
import org.springframework.stereotype.Service;

@Service
public class UserRoleServiceImpl implements UserRoleService {
	private final UserRoleRepository userRoleRepository;
	public UserRoleServiceImpl(UserRoleRepository userRoleRepository) {
		this.userRoleRepository = userRoleRepository;
	}

	@Override
	public UserRole save(UserRole userRole) {
		return userRoleRepository.save(userRole);
	}
}
