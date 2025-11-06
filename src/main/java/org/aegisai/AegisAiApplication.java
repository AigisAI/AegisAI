package org.aegisai;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication  // exclude 제거
@EnableJpaRepositories("org.aegisai.repository")  // Repository 스캔
@EntityScan("org.aegisai.entity")                  // Entity 스캔
public class AegisAiApplication {
    public static void main(String[] args) {
        SpringApplication.run(AegisAiApplication.class, args);
    }
}