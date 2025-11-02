package org.aegisai.service;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class ApiService {

    private final WebClient webClient;
    @Autowired
    public ApiService(WebClient.Builder webClientBuilder) {
        // 기본 URL 등 공통 설정을 여기서 할 수 있습니다.
        this.webClient = webClientBuilder.baseUrl("https://api.example.com").build();
    }

    private WebClient.Builder webClientBuilder;

    public Flux<VulnerabilitiesDto> request(AnalysisDto analysisDto) {
        WebClient webClient = webClientBuilder.build();

        return webClient.post() // GET -> POST (혹은 외부 API 스펙에 맞게)
                .uri("/scan-endpoint") // 실제 요청할 경로
                .bodyValue(analysisDto) // bodyValue 또는 body(BodyInserters.fromValue) 사용
                .retrieve() // 응답 수신
                .bodyToFlux(VulnerabilitiesDto.class); // String.class -> Dto.class
    }

}
