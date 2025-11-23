package org.aegisai.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.aegisai.entity.Analysis;
import org.aegisai.entity.Vulnerability;
import org.aegisai.repository.AnalysisRepository;
import org.aegisai.repository.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ApiService {
    private final WebClient webClient_model1;
    private final WebClient webClient_model2;
    private final GeminiService geminiService;
    private final AnalysisRepository analysisRepository;
    private final VulnerabilityRepository vulnerabilityRepository;


    @Autowired
    public ApiService(WebClient.Builder webClientBuilder,
                      AnalysisRepository analysisRepository,
                      VulnerabilityRepository vulnerabilityRepository,
                      GeminiService geminiService, @Value("${huggingface.api.token}")String apiToken) {
        this.webClient_model1 = webClientBuilder //codebert
                .baseUrl("https://router.huggingface.co/hf-inference/models/mrm8488/codebert-base-finetuned-detect-insecure-code")
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + apiToken)
                .build();

        this.webClient_model2 = webClientBuilder //code t5
                .baseUrl("http://34.50.3.152:8000") //
                .build();
        
        this.analysisRepository = analysisRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.geminiService = geminiService;

    }

    public Integer requestModel1(AnalysisDto analysisDto){
        //vulnerable status generate
        String codeSnippet = analysisDto.getCode();
        if (codeSnippet == null || codeSnippet.trim().isEmpty()) {
            System.err.println("API 호출 오류: Model 1 - 코드가 null이거나 비어있습니다.");
            return -1; // 오류 코드 반환
        }
        // Python의 {"inputs": "..."}와 동일한 구조의 Map 생성
        Map<String, String> payload = Map.of("inputs", codeSnippet);

        return webClient_model1.post()
                //.uri("/")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                // [!] 2. Integer가 아닌 JsonNode로 응답을 받습니다.
                .bodyToMono(JsonNode.class)
                .map(rootNode -> { // [!] 3. 받은 JsonNode를 파싱합니다.
                    try {
                        // 응답 형식: [[ {"label": "LABEL_1", ...} ]]
                        String label = rootNode.get(0).get(0).get("label").asText();

                        // [!] 4. 레이블을 Integer로 변환합니다.
                        return "LABEL_1".equals(label) ? 1 : 0;

                    } catch (Exception e) {
                        System.err.println("API 응답 파싱 실패: " + e.getMessage());
                        return -1; // 파싱 오류 시 -1
                    }
                })
                .block(); // 동기식으로 Integer 결과를 기다림
    }


    public String requestModel2(AnalysisDto analysisDto) {
        //fixed code generate
        String codeSnippet = analysisDto.getCode();
        if (codeSnippet == null || codeSnippet.trim().isEmpty()) {
            System.err.println("API 호출 오류: Model 2 - 코드가 null이거나 비어있습니다.");
            return "Error: Input code is empty"; // 오류 반환
        }

        // [!] 서버가 요구하는 정확한 JSON 페이로드 생성
        // {"text": "...", "max_length": 512, "temperature": 0.1}
        Map<String, Object> payload = Map.of(
                "text", codeSnippet,       // "inputs"가 아니라 "text"
                "max_length", 512,
                "temperature", 0.1
        );

        // fixed code generate
        return webClient_model2.post()
                .uri("/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload) // [✅] 'analysisDto' 대신 생성한 'payload' 전송
                .retrieve()
                .bodyToMono(String.class)
                .block();

        /*
        // 🆕 fixed code generate - 변수에 저장
        String fixedCode = webClient_model2.post()
                .uri("/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        // 🆕 줄바꿈 처리: \\n을 실제 줄바꿈(\n)으로 변환
        if (fixedCode != null) {
            fixedCode = fixedCode.replace("\\n", "\n");
            // 필요하면 탭 문자도 처리
            fixedCode = fixedCode.replace("\\t", "\t");
        }

        return fixedCode;
         */

    }
    public String requestModel3(AnalysisDto analysisDto){
        //judgement reason generate for vulnerable status
        return geminiService.reasonCodebert(analysisDto.getCode());

    }

    public String requestModel3_1(AnalysisDto analysisDto){
        //judgement reason generate for code fix
        return geminiService.reasonCodet5(analysisDto.getCode(), analysisDto.getFixedCode());

    }

    public List<VulnerabilitiesDto> requestModel4(AnalysisDto analysisDto) {
        try {
            List<VulnerabilitiesDto> vulnerabilities = geminiService.analyzeVulnerabilities(
                    analysisDto.getCode(),
                    analysisDto.getFixedCode()
            );

            // 3. 결과 로깅 (선택사항)
            System.out.println("발견된 취약점 수: " + vulnerabilities.size());

            return vulnerabilities;

        } catch (Exception e) {
            e.printStackTrace();
            // 에러 발생 시 빈 리스트 반환
            return new ArrayList<>();
        }
    }

    @Transactional // 트랜잭션 필수
    public void entityService(List<VulnerabilitiesDto> vulnerabilities, AnalysisDto analysisDto) {
        
        // 1. 외부 API에서 취약점 데이터 가져오기

        // 2. Analysis 엔티티 생성 및 저장
        Analysis analysis = Analysis.builder()
                .inputCode(analysisDto.getCode())
                .fixedCode(analysisDto.getFixedCode())
                .build();
        
        Analysis savedAnalysis = analysisRepository.save(analysis);
        System.out.println("✅Analysis 저장 완료: ID = " + savedAnalysis.getAnalysisId());
        
        // 3. Vulnerability 엔티티 변환 및 저장 (Enum 사용 안함)
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            List<Vulnerability> vulEntities = vulnerabilities.stream()
                    .map(dto -> Vulnerability.builder()
                            .analysis(savedAnalysis)
                            .message(dto.getMessage())
                            .lineNumber(dto.getLineNumber())
                            .codeSnippet(dto.getCodeSnippet())
                            .severity(dto.getSeverity())
                            .cweLink(dto.getCweLink())
                            .build())
                    .collect(Collectors.toList());
            
            vulnerabilityRepository.saveAll(vulEntities);
            System.out.println("Vulnerability " + vulEntities.size() + "개 저장 완료");
            
        }
    }

    // 🆕securityScore 계산 메서드
    public Integer calculateSecurityScore(List<VulnerabilitiesDto> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 100;
        }

        int totalDeduction = 0;

        for (VulnerabilitiesDto vuln : vulnerabilities) {
            String severity = vuln.getSeverity();
            if (severity == null) continue;

            switch (severity) {
                case "Critical":
                    totalDeduction += 25;
                    break;
                case "critical":
                    totalDeduction += 25;
                    break;
                case "High":
                    totalDeduction += 15;
                    break;
                case "high":
                    totalDeduction += 15;
                    break;
                case "Medium":
                    totalDeduction += 10;
                    break;
                case "medium":
                    totalDeduction += 10;
                    break;
                case "Low":
                    totalDeduction += 5;
                    break;
                case "low":
                    totalDeduction += 5;
                    break;
            }
        }

        return Math.max(0, 100 - totalDeduction);
    }
    
    // String을 SeverityStatus Enum으로 변환하는 헬퍼 메서드 (Enum 사용 안함)
    /*private SeverityStatus convertToSeverityEnum(String severity) {
        if (severity == null) {
            return SeverityStatus.LOW; // 기본값
        }
        
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return SeverityStatus.CRITICAL;
            case "HIGH":
                return SeverityStatus.HIGH;
            case "MEDIUM":
                return SeverityStatus.MEDIUM;
            case "LOW":
                return SeverityStatus.LOW;
            default:
                System.out.println("⚠️  알 수 없는 severity 값: " + severity + " → LOW로 변환");
                return SeverityStatus.LOW;
        }
    }*/
    
}