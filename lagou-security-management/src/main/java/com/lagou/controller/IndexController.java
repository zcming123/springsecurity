package com.lagou.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 初始页
 */
@Controller
public class IndexController {

    @RequestMapping("/")
    public String index(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("request getAttributeNames = " + request.getAttribute("_csrf"));
        CsrfToken csrf = (CsrfToken)request.getAttribute("_csrf");
        System.out.println("csrf Token = " + csrf.getToken());

        return "index";
    }

}
