package com.km.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * <p></p>
 * Created by zhezhiyong@163.com on 2017/9/20.
 */
@Entity
@Data
public class Role {

    @Id
    @GeneratedValue
    private Long id;
    private String roleName;
}
