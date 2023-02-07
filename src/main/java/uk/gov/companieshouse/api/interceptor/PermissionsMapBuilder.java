package uk.gov.companieshouse.api.interceptor;

public interface PermissionsMapBuilder {
    PermissionsMapping.PermissionsMappingBuilder mapAllOf(final String key, final String ... values);

    PermissionsMapping.PermissionsMappingBuilder mapNone(final String key);
}
