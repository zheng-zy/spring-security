package com.km.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * <p>View的Controller</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Configuration
public class WebMvcConfig extends WebMvcConfigurerAdapter {

    /**
     * 统一注册纯RequestMapping跳转View的Controller
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("/index");
        registry.addViewController("/login").setViewName("/login");
        registry.addViewController("/about").setViewName("/about");
        registry.addViewController("/index").setViewName("/index");
        registry.addViewController("/403").setViewName("/error/403");
    }
}
