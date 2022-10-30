package com.lagou.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 处理登录业务
 */
@Controller
public class LoginController {
    /**
     * 跳转登录页面
     *
     * @return
     */
    @RequestMapping("/toLoginPage")
    public String toLoginPage() {
        return "login";
    }

    @RequestMapping("/toLoginPage1")
    public String toLoginPage1() {
        return "toLoginPage1";
    }
    @RequestMapping("/toLoginPage2")
    public String toLoginPage2() {
        return "toLoginPage2";
    }
}
