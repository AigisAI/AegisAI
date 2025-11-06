package org.aegisai;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

<<<<<<< HEAD
@SpringBootApplication  // exclude 제거
@EnableJpaRepositories("org.aegisai.repository")  // Repository 스캔
@EntityScan("org.aegisai.entity")                  // Entity 스캔
=======
@SpringBootApplication
>>>>>>> cde6c049d1d44d84a0c18b997572cc58d72281ab
public class AegisAiApplication {
    public static void main(String[] args) {
        SpringApplication.run(AegisAiApplication.class, args);
    }
}