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
    //vulnerable status
    private String llmresponse2;
    //fixed code
    private String llmresponse3;
    //vulnerable reason
    private String llmresponse3_1;
    //fix reason

    private List<VulnerabilitiesDto> vulnerabilities;

    public ResponseDto(String status, String message, Integer llmresponse1) {
        this.status = status;
        this.message = message;
        this.llmresponse1 = llmresponse1;
    }


}
