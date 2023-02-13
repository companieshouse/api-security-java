package uk.gov.companieshouse.api.interceptor;

public interface PermissionsMapBuilder {
    PermissionsMapping.PermissionsMappingBuilder mappedRequireAnyOf(final String key, final String ... values);

    PermissionsMapping.PermissionsMappingBuilder mappedRequireNone(final String key);
}
