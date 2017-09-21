package com.km.dao;

import com.km.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Repository
public interface UserRoleDao extends JpaRepository<UserRole, Long>, JpaSpecificationExecutor<UserRole> {

    List<UserRole> findByUserId(Long userId);

}