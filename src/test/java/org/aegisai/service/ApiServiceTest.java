package org.aegisai.service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aegisai.dto.AnalysisDto;
import org.aegisai.repository.AnalysisRepository;
import org.aegisai.repository.VulnerabilityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock; // InjectMocks는 제거
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders; // HttpHeaders 임포트
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class ApiServiceTest {

    // 1. 모든 의존성은 @Mock으로 유지합니다.
    @Mock
    private WebClient.Builder webClientBuilder;
    @Mock
    private WebClient webClient_model1; // ApiService의 필드명과 일치
    @Mock
    private WebClient webClient_model2; // ApiService의 필드명과 일치
    @Mock
    private AnalysisRepository analysisRepository;
    @Mock
    private VulnerabilityRepository vulnerabilityRepository;
    @Mock
    private GeminiService geminiService;

    // 2. @InjectMocks를 제거하고, 필드만 선언합니다.
    private ApiService apiService;

    // 3. setUp 메서드에서 Mock을 설정하고, apiService를 수동 생성합니다.
    @BeforeEach
    void setUp() {
        // ... (setUp 코드는 이전과 동일)
        // (when(webClientBuilder.baseUrl(anyString())).thenReturn(webClientBuilder); 등)

        when(webClientBuilder.baseUrl(anyString())).thenReturn(webClientBuilder);

        // 2. defaultHeader(...)가 (어떤 인자들로) 호출되면, webClientBuilder 자신을 반환
        when(webClientBuilder.defaultHeader(anyString(), any())).thenReturn(webClientBuilder);

        // 3. build()가 호출될 때의 동작 설정
        //    (첫 번째 호출은 model1, 두 번째 호출은 model2 반환)
        when(webClientBuilder.build())
                .thenReturn(webClient_model1)
                .thenReturn(webClient_model2);

        // --- ⬆️ [수정] 설정 완료 ---

        // 4. 모든 Mock 설정이 끝난 후, 수동으로 apiService 생성 (이 줄이 59번째 줄입니다)
        //    이제 생성자가 실행되어도 NPE가 발생하지 않습니다.
        apiService = new ApiService(webClientBuilder, analysisRepository, vulnerabilityRepository, geminiService);}

    @Test
    void requestModel1_성공_케이스() throws Exception {
        // --- 1. Arrange (준비) ---
        AnalysisDto dto = new AnalysisDto("public class Test {}", null);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode mockResponse = mapper.readTree("[[{\"label\": \"LABEL_1\", \"score\": 0.99}]]");
        Mono<JsonNode> monoJsonNode = Mono.just(mockResponse);

        // --- ⬇️ [수정] WebClient 모의(Mocking) 체인 ⬇️ ---

        // 1. 필요한 모든 스펙(Spec) 인터페이스를 Mock으로 생성
        WebClient.RequestBodyUriSpec mockUriSpec = Mockito.mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec mockBodySpec = Mockito.mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec mockHeadersSpec = Mockito.mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec mockResponseSpec = Mockito.mock(WebClient.ResponseSpec.class);

        // 2. 전체 체인을 순서대로 설정
        when(webClient_model1.post()).thenReturn(mockUriSpec);

        // 3. (추가된 부분) .uri() 호출 설정
        when(mockUriSpec.uri(anyString())).thenReturn(mockBodySpec);

        // 4. .contentType(), .bodyValue() 등 나머지 체인 설정
        when(mockBodySpec.contentType(any(MediaType.class))).thenReturn(mockBodySpec);
        when(mockBodySpec.bodyValue(any(Map.class))).thenReturn(mockHeadersSpec);
        when(mockHeadersSpec.retrieve()).thenReturn(mockResponseSpec);
        when(mockResponseSpec.bodyToMono(eq(JsonNode.class))).thenReturn(monoJsonNode);

        // --- ⬆️ 모의(Mocking) 수정 완료 ⬆️ ---

        // --- 2. Act (실행) ---
        Integer result = apiService.requestModel1(dto);

        // --- 3. Assert (검증) ---
        assertEquals(1, result);

}

    @Test
    void requestModel2() {
    }

    @Test
    void requestModel3() {
    }

    @Test
    void requestModel3_1() {
    }

    @Test
    void requestModel4() {
    }
}