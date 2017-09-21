### spring boot spring security学习

目的在于搭建一个可以在生产使用，基于spring boot+spring security+thymeleaf开发的权限示例。

1. 前段页面权限显示
2. url服务端权限验证
3. 密码md5加密
4. 登录日志

### 项目说明

/login /about /403 不需要任何权限
/admin 管理员权限
/user 用户权限 管理员权限
/test 测试系统无权限显示


### 项目依赖
```pom.xml

	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>1.5.7.RELEASE</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.thymeleaf.extras</groupId>
        <artifactId>thymeleaf-extras-springsecurity4</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <scope>compile</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>1.2.38</version>
    </dependency>
    <!-- hot swapping, disable cache for template, enable live reload -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <optional>true</optional>
    </dependency>
    <!-- Optional, for bootstrap -->
    <dependency>
        <groupId>org.webjars</groupId>
        <artifactId>bootstrap</artifactId>
        <version>3.3.7</version>
    </dependency>
```
### Spring Security
``` 
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
    public LoginSuccessHandler loginSuccessHandler(){
        return new LoginSuccessHandler();
    }
}
```
### 定义全局异常处理
```
/**
 * <p>异常处理</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandlerAdvice {

    @ExceptionHandler(Throwable.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String exception(final Throwable throwable, final Model model) {
//        log.error("Exception during execution of SpringSecurity application", throwable);
        String errorMessage = (throwable != null ? throwable.getMessage() : "Unknown error");
        model.addAttribute("errorMessage", errorMessage);
        return "error";
    }

}
```
当前只定义了http status 500 异常处理，如有需要可以自己定义其它

### 定义登录日志记录类
```
/**
 * <p>登录日志</p>
 * Created by zhezhiyong@163.com on 2017/9/21.
 */
@Slf4j
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        User user = (User) authentication.getPrincipal();
        log.info("当前登录用户: {}, ip地址: {}", user.getUsername(), getIpAddress(request));
        super.onAuthenticationSuccess(request, response, authentication);
    }

    public String getIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}
```
### 定义403权限访问，无权限记录日志并跳转

```
/**
 * <p>定义403权限访问，无权限记录日志并跳转</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Component
@Slf4j
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            log.info("User '" + auth.getName()
                    + "' attempted to access the protected URL: "
                    + httpServletRequest.getRequestURI());
        }
        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/403");
    }
}
```
### 定义view跳转
```
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
```

### 定义用户数据和权限，和数据库关联

```
/**
 * <p>定义用户数据和权限，和数据库关联</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Slf4j
public class LightSwordUserDetailService implements UserDetailsService {

    @Autowired
    private UserDao userDao;
    @Autowired
    private RoleDao roleDao;
    @Autowired
    private UserRoleDao userRoleDao;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userDao.findByUserName(userName);
        if (null == user) throw new UsernameNotFoundException(userName + " not found");
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        List<UserRole> userRoleList = userRoleDao.findByUserId(user.getId());
        userRoleList.forEach(userRole -> {
            Role role = roleDao.findOne(userRole.getRoleId());
            if (role.getRoleName() != null) authorityList.add(new SimpleGrantedAuthority(role.getRoleName()));
        });
        log.info("{}-{}", userName, JSON.toJSONString(authorityList));
        return new org.springframework.security.core.userdetails.User(userName, user.getPassword(), authorityList);
    }
}

```

### md5加密算法

```
/**
 * <p>md5加密算法</p>
 * Created by zhezhiyong@163.com on 2017/9/21.
 */
public class MD5Util {

    private static final String SALT = "salt";

    public static String encode(String password) {
        password = password + SALT;
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        char[] charArray = password.toCharArray();
        byte[] byteArray = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++)
            byteArray[i] = (byte) charArray[i];
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuilder hexValue = new StringBuilder();
        for (byte md5Byte : md5Bytes) {
            int val = ((int) md5Byte) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    public static void main(String[] args) {
        System.out.println(MD5Util.encode("666666"));
    }

}
```

### IndexController

```
/**
 * <p>IndexController</p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Controller
public class IndexController {

    @RequestMapping("/test")
    public String test(){
        return "test";
    }

    @RequestMapping("/loginError")
    public String loginError(Model model){
        model.addAttribute("loginError", true);
        return "login";
    }

    @RequestMapping("/user")
    @PreAuthorize("hasAnyAuthority('user', 'admin')")
    public String user(){
        return "user";
    }

    @RequestMapping("/testError")
    @PreAuthorize("hasAuthority('admin','user')")
    public String error(){
        return "user";
    }

    @RequestMapping("/admin")
    @PreAuthorize("hasAuthority('admin')")
    public String admin(){
        return "admin";
    }

}
```

### 配置程序启动

```
@SpringBootApplication
public class SpringbootSpringsecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringbootSpringsecurityApplication.class, args);
	}
}
```

```application.yml
server:
  port: 8080
spring:
  application:
    name: spring-security
  jpa:
    generate-ddl: false
    show-sql: true
    hibernate:
      ddl-auto: none
  datasource:                           # 指定数据源
    platform: h2                        # 指定数据源类型
    schema: classpath:schema.sql        # 指定h2数据库的建表脚本
    data: classpath:data.sql            # 指定h2数据库的数据脚本
logging:                                # 配置日志级别，让hibernate打印出执行的SQL
  level:
    root: INFO
    org.hibernate: INFO
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    org.hibernate.type.descriptor.sql.BasicExtractor: TRACE
```

```schema.sql
drop table user if exists;
drop table role if exists;
drop table userrole if exists;
create table user (id bigint generated by default as identity, user_name varchar(40), password varchar(40));
create table role (id bigint generated by default as identity, role_name varchar(40));
create table user_role (id bigint generated by default as identity, user_id bigint(20), role_id bigint(20));
```

```data.sql
insert into user (id, user_name, password) values (1, 'admin', 'e97c15df9188958552f27736979e9a5d');
insert into user (id, user_name, password) values (2, 'dev', 'e97c15df9188958552f27736979e9a5d');
insert into user (id, user_name, password) values (3, 'test', 'e97c15df9188958552f27736979e9a5d');
insert into role (id, role_name) values (1, 'admin');
insert into role (id, role_name) values (2, 'user');
insert into user_role (id, user_id, role_id) values (1, 1, 1);
insert into user_role (id, user_id, role_id) values (2, 2, 1);
insert into user_role (id, user_id, role_id) values (3, 2, 2);
insert into user_role (id, user_id, role_id) values (4, 3, 2);
```

密码是：666666

### 定义页眉页脚

```common/header.html
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <div th:fragment="header-css">
        <!-- this is header-css -->
        <link rel="stylesheet" type="text/css" href="webjars/bootstrap/3.3.7/css/bootstrap.min.css"/>
        <link rel="stylesheet" th:href="@{/css/main.css}" href="/static/css/main.css"/>
    </div>
</head>
<body>
<div th:fragment="header">
    <!-- this is header -->
    <nav class="navbar navbar-inverse">
        <div class="container">
            <div class="navbar-header">
                <a class="navbar-brand" th:href="@{/}">Spring Boot</a>
            </div>
            <div id="navbar" class="collapse navbar-collapse">
                <ul class="nav navbar-nav">
                    <li class="active"><a th:href="@{/}">Home</a></li>
                </ul>
            </div>
        </div>
    </nav>
</div>

</body>
</html>
```

```common/footer.html
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity4">
<head>
</head>
<body>
<div th:fragment="footer">

    <div class="container">

        <footer>
            <!-- this is footer -->
            &copy; 2017 www.ktvme.com
            <span sec:authorize="isAuthenticated()">
                | Logged user: <span sec:authentication="name"></span> |
                Roles: <span sec:authentication="principal.authorities"></span> |
                <a th:href="@{/logout}">Sign Out</a>
            </span>
            <script src="https://cdn.bootcss.com/jquery/1.12.4/jquery.min.js"></script>
            <script type="text/javascript" src="webjars/bootstrap/3.3.7/js/bootstrap.min.js"></script>
        </footer>
    </div>

</div>
</body>
</html>
```

### 定义登录界面

```login.html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Spring Security Example </title>
    <div th:replace="common/header :: header-css"/>
</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="row" style="margin-top:20px">
        <div class="col-xs-12 col-sm-8 col-md-6 col-sm-offset-2 col-md-offset-3">
            <form th:action="@{/login}" method="post">
                <fieldset>
                    <h1>Please Sign In</h1>
                    <!--错误回显-->
                    <div th:if="${loginError}">
                        <div class="alert alert-danger">
                            Invalid username and password.
                        </div>
                    </div>

                    <div class="form-group">
                        <input type="text" name="username" id="username" class="form-control input-lg"
                               placeholder="UserName" required="true" autofocus="true"/>
                    </div>
                    <div class="form-group">
                        <input type="password" name="password" id="password" class="form-control input-lg"
                               placeholder="Password" required="true"/>
                    </div>

                    <div class="row">
                        <div class="col-xs-6 col-sm-6 col-md-6">
                            <input type="submit" class="btn btn-lg btn-primary btn-block" value="Sign In"/>
                        </div>
                        <div class="col-xs-6 col-sm-6 col-md-6">
                            <!--<label><input type="checkbox" id="rememberme" name="remember-me"/> Remember Me</label>-->
                        </div>
                    </div>
                </fieldset>
            </form>
        </div>
    </div>

</div>

<div th:replace="common/footer :: footer"/>

</body>
</html>
```

### 定义主页面

```index.html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Spring Boot Thymeleaf + Spring Security</title>

    <div th:replace="common/header :: header-css"/>

</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="starter-template">
        <h1>Spring Boot Web Thymeleaf + Spring Security</h1>
        <h2>1. Visit <a th:href="@{/admin}">Admin page (Spring Security protected, Need Admin Role)</a></h2>
        <h2>2. Visit <a th:href="@{/user}">User page (Spring Security protected, Need User Role)</a></h2>
        <h2>2. Visit <a th:href="@{/testError}">Error page (Spring Security protected, Need User Role)</a></h2>
        <h2>3. Visit <a th:href="@{/about}">Normal page</a></h2>
    </div>

</div>
<!-- /.container -->

<div th:replace="common/footer :: footer"/>

</body>
</html>
```
### 定义管理员，用户，测试错误403界面，关于界面

```admin.html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <div th:replace="common/header :: header-css"/>
</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="starter-template">
        <h1>Admin page (Spring Security protected)</h1>

        <h1 th:inline="text">Hello [[${#httpServletRequest.remoteUser}]]!</h1>

        <h1><a th:href="@{/index}">返回主页</a></h1>
    </div>

</div>
<!-- /.container -->

<div th:replace="common/footer :: footer"/>

</body>
</html>
```
```user.html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <div th:replace="common/header :: header-css"/>
</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="starter-template">
        <h1>User page (Spring Security protected)</h1>
        <h1 th:inline="text">Hello [[${#httpServletRequest.remoteUser}]]!</h1>
        <h1><a th:href="@{/index}">返回主页</a></h1>
    </div>

</div>
<!-- /.container -->
<div th:replace="common/footer :: footer"/>

</body>
</html>
```
```common/403.html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <div th:replace="common/header :: header-css"/>
</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="starter-template">
        <h1>403 - Access is denied</h1>
        <div th:inline="text">Hello '[[${#httpServletRequest.remoteUser}]]', you do not have permission to access this page.</div>
    </div>

</div>
<!-- /.container -->

<div th:replace="common/footer :: footer"/>

</body>
</html>
```
```about.html
<!DOCTYPE HTML>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <div th:replace="common/header :: header-css"/>
</head>
<body>

<div th:replace="common/header :: header"/>

<div class="container">

    <div class="starter-template">
        <h1>Normal page (No need login)</h1>

        <h1><a th:href="@{/index}">返回主页</a></h1>
    </div>

</div>
<!-- /.container -->

<div th:replace="common/footer :: footer"/>

</body>
</html>
```

### css样式
```static/css/main.css
h1 {
    color: #0000FF;
}

h2 {
    color: #FF0000;
}

footer {
    margin-top: 60px;
}
```

### 示例

![image](https://git.oschina.net/zhengzy/md/raw/master/pic/spring-security/1.png)
[如果对你有帮助请赏赐一个star](https://github.com/zheng-zy/spring-security.git)

