package com.km.security;

import com.alibaba.fastjson.JSON;
import com.km.dao.RoleDao;
import com.km.dao.UserDao;
import com.km.dao.UserRoleDao;
import com.km.entity.Role;
import com.km.entity.User;
import com.km.entity.UserRole;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

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
