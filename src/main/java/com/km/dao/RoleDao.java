package com.km.dao;

import com.km.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Repository
public interface RoleDao extends JpaRepository<Role, Long>, JpaSpecificationExecutor<Role> {


}
