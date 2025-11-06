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
        Integer result = apiService.requestModel1(analysisDto); //code bert
        if (result==0) {
            body = new ResponseDto("200", "안전한 코드입니다.",0);
            return ResponseEntity.ok(body).getBody();
        }
        else {
            body = new ResponseDto("VULNERABLE", "취약한 코드입니다.",1);
        }
        body.setLlmresponse3(apiService.requestModel3(analysisDto)); //llm
        body.setLlmresponse2(apiService.requestModel2(analysisDto)); //code t5
        body.setLlmresponse3(apiService.requestModel3(analysisDto)); //llm
        List<VulnerabilitiesDto> vulnerabilities = apiService.entityService(apiService.requestModel4(analysisDto), analysisDto); //guide llm
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
