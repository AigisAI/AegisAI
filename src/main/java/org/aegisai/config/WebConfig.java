package org.aegisai.config; // 패키지 경로는 맞게 수정하세요

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry; // <-- import 경로가 'servlet'으로 바뀜
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer; // <-- 'WebFluxConfigurer'가 아님

@Configuration
public class WebConfig implements WebMvcConfigurer { // WebMvcConfigurer

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 1. 모든 경로(/)에 대해
                .allowedOrigins("http://localhost:5173", "http://127.0.0.1:5173","http://localhost:3000", "http://15.164.13.20:5173","http://15.164.13.20:8080") // 2. React 서버 주소
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // 3. 허용할 HTTP 메서드
                .allowedHeaders("*") // 4. 허용할 헤더
                .allowCredentials(true); // 5. 쿠키 등 허용
    }
}