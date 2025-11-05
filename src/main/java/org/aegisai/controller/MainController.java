package org.aegisai.controller;

import org.hibernate.jdbc.Expectation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class MainController {

    @GetMapping("/")
    public String main(){
    return "forward:/index";
    }

}
