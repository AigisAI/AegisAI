package org.aegisai.service;

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

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ApiService {

    private final WebClient webClient;
    private final AnalysisRepository analysisRepository;
    private final VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    public ApiService(WebClient.Builder webClientBuilder,
                      AnalysisRepository analysisRepository,
                      VulnerabilityRepository vulnerabilityRepository) {
        this.webClient = webClientBuilder
                .baseUrl("https://38b4f941-fec7-45cf-8e5e-0bbf1bf2336d.mock.pstmn.io")
                .build();
        this.analysisRepository = analysisRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    @Transactional // 트랜잭션 필수
    public List<VulnerabilitiesDto> request(AnalysisDto analysisDto) {
        
        // 1. 외부 API에서 취약점 데이터 가져오기
        List<VulnerabilitiesDto> vulnerabilities = webClient.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(analysisDto)
                .retrieve()
                .bodyToFlux(VulnerabilitiesDto.class)
                .collectList()
                .block();

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