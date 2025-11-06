package org.aegisai.controller;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.ResponseDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.aegisai.service.ApiService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@RestController
public class ApiController {

    private final ApiService apiService;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    @PostMapping("/api/scan-vulnerability")
    public ResponseDto requestApi(@RequestBody AnalysisDto analysisDto) {
        ResponseDto body;

        // 1. CodeBERT로 취약점 여부 확인
        Integer result = apiService.requestModel1(analysisDto);
        
        if (result==0) {
            // 안전한 코드인 경우
            body = new ResponseDto("200", "안전한 코드입니다.");
            return ResponseEntity.ok(body).getBody();
        }
        else {
            body = new ResponseDto("VULNERABLE", "취약한 코드입니다.");
        }
        
        body.setXaiDetectionExplanation(apiService.requestModel3(analysisDto)); //llm(프롬프트 필요)
        analysisDto.setFixedcode(apiService.requestModel2(analysisDto)); //code t5
        body.setXaiFixExplanation(apiService.requestModel3_1(analysisDto)); //llm(프롬프트 필요)
        List<VulnerabilitiesDto> vulnerabilities = apiService.requestModel4(analysisDto); //guide llm
        apiService.entityService(vulnerabilities, analysisDto);
        
        //프롬프트 필요
        body.setVulnerabilities(vulnerabilities);

        return body;
    }

    @PostMapping("/api/token-count")
    public ResponseEntity<Map> countTokens(@RequestBody String code) {
        String url = "http://localhost:8000/token-count"; // Python 서버 주소

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> entity = new HttpEntity<>(code, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> resp = restTemplate.postForEntity(url, entity, Map.class);

        return ResponseEntity.ok(resp.getBody());
    }
}
