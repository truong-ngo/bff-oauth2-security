package com.example.authorizationserver.service.mapper;

import com.example.authorizationserver.entity.UserDomain;
import com.example.authorizationserver.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.util.ArrayList;
import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper extends EntityMapper<UserDomain, User> {

    @Override
    @Mapping(source = "roles", target = "roles", qualifiedByName = "listToStr")
    UserDomain toEntity(User dto);

    @Override
    @Mapping(source = "roles", target = "roles", qualifiedByName = "strToList")
    User toDto(UserDomain entity);

    @Named("listToStr")
    default String toRoleString(List<String> roles) {
        return String.join(",", roles);
    }

    @Named("strToList")
    default List<String> toRoleList(String roles) {
        return new ArrayList<>(List.of(roles.split(",")));
    }
}
