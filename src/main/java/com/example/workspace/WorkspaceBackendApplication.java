package com.example.workspace;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class WorkspaceBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(WorkspaceBackendApplication.class, args);
	}

}
