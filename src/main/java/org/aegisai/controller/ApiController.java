package org.aegisai.controller;

import org.aegisai.dto.AnalysisDto;
import org.aegisai.dto.VulnerabilitiesDto;
import org.aegisai.service.ApiService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class ApiController {

    private ApiService apiService;
    public void apiService(ApiService apiService){
        this.apiService=apiService;
    }

    @PostMapping("/api/scan-vulnerability")
    public List<VulnerabilitiesDto> requestApi(@RequestBody AnalysisDto analysisDto) {

        return apiService.request(analysisDto);
    }


}
