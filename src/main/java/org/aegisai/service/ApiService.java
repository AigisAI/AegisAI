package org.aegisai.service;

import org.aegisai.constant.AnalysisStatus;
import org.aegisai.constant.SeverityStatus;
import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ApiService {
    private WebClient webClient_model1;
    private WebClient webClient_model2;
    private WebClient webClient_model3;
    private final AnalysisRepository analysisRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    public ApiService(WebClient.Builder webClientBuilder,
                      AnalysisRepository analysisRepository,
                                  Repository vulnerabilityRepository) {
        WebClient webClient_model1 = webClientBuilder //codebert
                .baseUrl("https://api-inference.huggingface.co/models/mrm8488/codebert-base-finetuned-detect-insecure-code")
                .build();
        WebClient webClient_model2 = webClientBuilder //code t5
                .baseUrl("http://34.47.124.100:8000")
                .build();
        WebClient webClient_model3 = webClientBuilder //gemini
                .baseUrl("https://38b4f941-fec7-45cf-8e5e-0bbf1bf2336d.mock.pstmn.io")
                .build();
        this.analysisRepository = analysisRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public Integer requestModel1(AnalysisDto analysisDto){
        //vulnerable status generate
        return webClient_model1.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(analysisDto)
                .retrieve()
                .bodyToMono(Integer.class) // Dto 목록이 아닌 Integer로 직접 받음
                .block();
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
        String prompt = "다음 코드에 대한 판정 이유를 생성해 주세요:";

        // 2. 요청 본문을 Map으로 만듭니다.
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("prompt", prompt);
        requestBody.put("analysis_data", analysisDto);
        return webClient_model3.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
    public String requestModel3_1(AnalysisDto analysisDto){
        //judgement reason generate for code fix
        String prompt = "기존코드 : AnalysisDto. R";

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("prompt", prompt);
        requestBody.put("analysis_data", analysisDto);
        return webClient_model3.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public List<VulnerabilitiesDto> requestModel4(AnalysisDto analysisDto){
        //guide generate
        return webClient_model3.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(analysisDto)
                .retrieve()
                .bodyToFlux(VulnerabilitiesDto.class)
                .collectList()
                .block();
    }
    @Transactional // 트랜잭션 필수
    public List<VulnerabilitiesDto> entityService(List<VulnerabilitiesDto> vulnerabilities, AnalysisDto analysisDto) {
        
        // 1. 외부 API에서 취약점 데이터 가져오기


        // 2. Analysis 엔티티 생성 및 저장
        Analysis analysis = Analysis.builder()
                .status(AnalysisStatus.COMPLETED)
                .highVulCount(0)
                .mediumVulCount(0)
                .lowVulCount(0)
                .build();
        
        Analysis savedAnalysis = analysisRepository.save(analysis);
        System.out.println("Analysis 저장 완료: ID = " + savedAnalysis.getAnalysisId());
        
        // 3. Vulnerability 엔티티 변환 및 저장
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            List<Vulnerability> vulEntities = vulnerabilities.stream()
                    .map(dto -> {
                        // String severity를 Enum으로 변환
                        SeverityStatus severityEnum = convertToSeverityEnum(dto.getSeverity());
                        
                        return Vulnerability.builder()
                                .analysis(savedAnalysis)
                                .message(dto.getMessage())
                                .lineNumber(dto.getLineNumber())
                                .codeSnippet(dto.getCodeSnippet())
                                .severity(severityEnum) // Enum 사용
                                .cweLink(dto.getCweLink())
                                .build();
                    })
                    .collect(Collectors.toList());
            
            vulnerabilityRepository.saveAll(vulEntities);
            System.out.println("Vulnerability " + vulEntities.size() + "개 저장 완료");
            
            // 4. 심각도별 카운트 업데이트
            long highCount = vulEntities.stream()
                    .filter(v -> v.getSeverity() == SeverityStatus.HIGH)
                    .count();
            long mediumCount = vulEntities.stream()
                    .filter(v -> v.getSeverity() == SeverityStatus.MEDIUM)
                    .count();
            long lowCount = vulEntities.stream()
                    .filter(v -> v.getSeverity() == SeverityStatus.LOW)
                    .count();
            
            savedAnalysis.completeAnalysis((int) highCount, (int) mediumCount, (int) lowCount);
            analysisRepository.save(savedAnalysis);
            System.out.println("Analysis 카운트 업데이트 완료");
        }
        return vulnerabilities;
    }
    
    // String을 SeverityStatus Enum으로 변환하는 헬퍼 메서드
    private SeverityStatus convertToSeverityEnum(String severity) {
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
    }
}