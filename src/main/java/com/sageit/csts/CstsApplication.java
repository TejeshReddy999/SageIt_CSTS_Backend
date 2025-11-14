package com.sageit.csts;

import com.sageit.csts.entities.Role;
import com.sageit.csts.repositories.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CstsApplication {

	private static final Logger logger = LoggerFactory.getLogger(CstsApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(CstsApplication.class, args);
		logger.info("CSTS Application started successfully");
	}

	@Bean
	CommandLineRunner initRoles(RoleRepository roleRepository) {
		return args -> {
			if (roleRepository.findByName("ROLE_USER").isEmpty()) {
				roleRepository.save(new Role(null, "ROLE_USER"));
				logger.info("ROLE_USER initialized");
			} else {
				logger.debug("ROLE_USER already exists");
			}

			if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
				roleRepository.save(new Role(null, "ROLE_ADMIN"));
				logger.info("ROLE_ADMIN initialized");
			} else {
				logger.debug("ROLE_ADMIN already exists");
			}
		};
	}
}
