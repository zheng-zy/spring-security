package com.km;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/21.
 */
public class TestAll {

    @Test
    public void testPassword() {
        String password = "test";
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode(password));
    }


}
