package com.km.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * <p>IndexController</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Controller
public class IndexController {

    @RequestMapping("/test")
    public String test() {
        return "test";
    }

    @RequestMapping("/loginError")
    public String loginError(Model model) {
        model.addAttribute("loginError", true);
        return "login";
    }

    @RequestMapping("/user")
    @PreAuthorize("hasAnyAuthority('user', 'admin')")
    public String user() {
        return "user";
    }

    @RequestMapping("/testError")
    @PreAuthorize("hasAuthority('admin','user')")
    public String error() {
        return "user";
    }

    @RequestMapping("/admin")
    @PreAuthorize("hasAuthority('admin')")
    public String admin() {
        return "admin";
    }

}
