package com.example.authorizationserver.service.mapper;

import org.mapstruct.BeanMapping;
import org.mapstruct.Named;
import org.mapstruct.NullValuePropertyMappingStrategy;

public interface EntityMapper<E, D> {
    E toEntity(D dto);

    D toDto(E entity);

    @Named("partialUpdate")
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    D partialUpdate(D dto);
}
