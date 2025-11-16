package org.aegisai.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class ResponseDto {

    private List<VulnerabilitiesDto> vulnerabilities;

    private String xaiDetectionExplanation;
    //vulnerable reason
    private String xaiFixExplanation;
    //fix reason

    private String fixedCode;

    private Integer securityScore; // securityScore 추가

    private String status;

    private String message;

    public ResponseDto(String status, String message) {
        this.status = status;
        this.message = message;
    }


}
