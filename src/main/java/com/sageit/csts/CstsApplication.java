package com.sageit.csts;

import com.sageit.csts.entities.Role;
import com.sageit.csts.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CstsApplication {

	public static void main(String[] args) {
		SpringApplication.run(CstsApplication.class, args);
	}

	@Bean
	CommandLineRunner initRoles(RoleRepository roleRepository) {
		return args -> {
			if (roleRepository.findByName("ROLE_USER").isEmpty()) {
				roleRepository.save(new Role(null,"ROLE_USER"));
			}
			if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
				roleRepository.save(new Role(null,"ROLE_ADMIN"));
			}
		};
	}

}
