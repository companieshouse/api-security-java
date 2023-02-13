package uk.gov.companieshouse.api.interceptor;

public interface PermissionsDefaultBuilder {
    PermissionsMapping.PermissionsMappingBuilder defaultRequireAnyOf(final String... values);

    PermissionsMapping.PermissionsMappingBuilder defaultRequireNone();
}
