package org.aegisai.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class ResponseDto {

    private String status;

    private String message;

    private Integer llmresponse1;

    private String llmresponse2;

    private String llmresponse3;

    private List<VulnerabilitiesDto> vulnerabilities;

    public ResponseDto(String status, String message, Integer llmresponse1) {
        this.status = status;
        this.message = message;
        this.llmresponse1 = llmresponse1;
    }


}
