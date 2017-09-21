package com.km.security;

import com.km.util.MD5Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * <p>security权限配置</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
// 使用这个注解，可以开启security的注解，我们可以在需要控制权限的方法上面使用@PreAuthorize，@PreFilter这些注解。
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        return new LightSwordUserDetailService();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService())
                .passwordEncoder(new PasswordEncoder() {
                    @Override
                    public String encode(CharSequence charSequence) {
                        return MD5Util.encode((String) charSequence);
                    }

                    @Override
                    public boolean matches(CharSequence charSequence, String s) {
                        return s.equals(MD5Util.encode((String) charSequence));
                    }
                }); //指定密码加密所使用的加密器为passwordEncoder()
        auth.eraseCredentials(false);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().disable().headers().disable()
                .authorizeRequests()
                .antMatchers("/login", "/about", "/403").permitAll()
                .antMatchers("/admin/**").hasAnyAuthority("admin")
                .antMatchers("/", "/user/**").hasAnyAuthority("admin", "user")
                //其他地址的访问均需验证权限
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login") //指定登录页是"/login"
                .defaultSuccessUrl("/") //登录成功后默认跳转到"/hello"
                .failureUrl("/loginError")
                .permitAll()
                .successHandler(loginSuccessHandler()) //登录日志
                .and()
                .logout().logoutSuccessUrl("/login") //退出登录后的默认url是"/home"
                .permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 默认不拦截静态资源的url pattern
        web.ignoring().antMatchers("/css/**");
        web.ignoring().antMatchers("/webjars/**");
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler();
    }
}
