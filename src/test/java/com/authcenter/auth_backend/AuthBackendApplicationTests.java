package com.authcenter.auth_backend;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestSecurityConfig.class)
class AuthBackendApplicationTests {
	@Test
	void contextLoads() {
	}
}
