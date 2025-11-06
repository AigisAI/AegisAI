package org.aegisai.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.aegisai.constant.AnalysisStatus;
import org.aegisai.constant.SeverityStatus;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.aegisai.entity.Analysis;
import org.aegisai.entity.Vulnerability;
import org.aegisai.repository.AnalysisRepository;
import org.aegisai.repository.VulnerabilityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ApiService {
    private WebClient webClient_model1;
    private WebClient webClient_model2;
    private WebClient webClient_model3;
    private final GeminiService geminiService;
    private final AnalysisRepository analysisRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    public ApiService(WebClient.Builder webClientBuilder,
                      AnalysisRepository analysisRepository,
                      VulnerabilityRepository vulnerabilityRepository,
                      GeminiService geminiService) {

        this.webClient_model1 = webClientBuilder //codebert
                .baseUrl("https://router.huggingface.co/hf-inference/models/mrm8488/codebert-base-finetuned-detect-insecure-code")
                .build();

        this.webClient_model2 = webClientBuilder //code t5
                .baseUrl("http://34.47.124.100:8000")
                .build();
        
        this.analysisRepository = analysisRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.geminiService = geminiService;

    }

    public Integer requestModel1(AnalysisDto analysisDto){
        //vulnerable status generate
        // API 응답은 ClassifierResponse[][] (2차원 배열) 형태입니다.
        return webClient_model1.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(analysisDto)
                .retrieve()
                .bodyToMono(JsonNode.class) // 1. 응답을 JsonNode로 받습니다.
                .map(rootNode -> {
                    // 2. JSON 구조 [[ {"label": ...} ]] 를 직접 탐색합니다.
                    try {
                        // rootNode.get(0) -> [ {"label": ...} ] (첫 번째 배열)
                        // rootNode.get(0).get(0) -> {"label": ...} (첫 번째 객체)
                        // rootNode.get(0).get(0).get("label") -> "LABEL_1" (label 값)
                        String label = rootNode.get(0).get(0).get("label").asText();

                        // 3. 레이블 문자열을 Integer로 변환합니다.
                        return "LABEL_1".equals(label) ? 1 : 0;

                    } catch (Exception e) {
                        // JsonNode 탐색 중 오류 발생 시 (예: API 응답 형식이 다른 경우)
                        System.err.println("API 응답 파싱 실패: " + e.getMessage());
                        return -1; // 오류를 나타내는 값 (예: -1)
                    }
                })
                .block(); // 동기식으로 결과를 기다림
    }


    public String requestModel2(AnalysisDto analysisDto){
        //fixed code generate
        return webClient_model2.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(analysisDto)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public String requestModel3(AnalysisDto analysisDto){
        //judgement reason generate for vulnerable status
        return geminiService.reasonCodebert(analysisDto.getInputcode());

    }

    public String requestModel3_1(AnalysisDto analysisDto){
        //judgement reason generate for code fix
        return geminiService.reasonCodet5(analysisDto.getInputcode(), analysisDto.getFixedcode());

    }

    public List<VulnerabilitiesDto> requestModel4(AnalysisDto analysisDto) {
        try {
            List<VulnerabilitiesDto> vulnerabilities = geminiService.analyzeVulnerabilities(
                    analysisDto.getInputcode(),
                    analysisDto.getFixedcode()
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
    public List<VulnerabilitiesDto> entityService(List<VulnerabilitiesDto> vulnerabilities, AnalysisDto analysisDto) {
        
        // 1. 외부 API에서 취약점 데이터 가져오기

        // 2. Analysis 엔티티 생성 및 저장
        Analysis analysis = Analysis.builder()
                .inputCode(analysisDto.getInputcode())
                .fixedCode(analysisDto.getFixedcode())
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
        return vulnerabilities;
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