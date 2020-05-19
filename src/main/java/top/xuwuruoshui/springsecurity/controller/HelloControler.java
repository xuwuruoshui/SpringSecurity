package top.xuwuruoshui.springsecurity.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloControler {

    @PostMapping("/hello")
    public String hello() {
        return "world";
    }
}