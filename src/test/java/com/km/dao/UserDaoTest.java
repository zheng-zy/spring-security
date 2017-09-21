package com.km.dao;

import com.km.entity.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class UserDaoTest {
    @Autowired
    private UserDao userDao;

    @Test
    public void findByUserName() throws Exception {
        User user = userDao.findByUserName("admin");
        System.out.println(user.toString());
    }

}