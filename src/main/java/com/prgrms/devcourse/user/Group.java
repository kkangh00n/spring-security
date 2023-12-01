package com.prgrms.devcourse.user;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Entity
@Table(name = "groups")
public class Group {

    @Id
    private Long id;

    private String name;

    @OneToMany(mappedBy = "group")
    private List<GroupPermission> permissions = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<GrantedAuthority> getAuthorities(){
        return permissions.stream()
            .map(gp -> new SimpleGrantedAuthority(gp.getPermission().getName()))
            .collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return "Group{" +
            "id=" + id +
            ", name='" + name + '\'' +
            ", authorities='" + getAuthorities() + '\'' +
            '}';
    }
}
