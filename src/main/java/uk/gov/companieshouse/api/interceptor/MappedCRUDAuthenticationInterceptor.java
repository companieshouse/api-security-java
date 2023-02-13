package uk.gov.companieshouse.api.interceptor;

import org.springframework.http.HttpMethod;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.TokenPermissions;

/**
 * <p>Alternative to {@link CRUDAuthenticationInterceptor} implemented with
 * {@link MappablePermissionsInterceptor}.</p>
 * <p>Checks the request contains the relevant token permission values based on the HTTP method.
 * It will try to find a {@link TokenPermissions} object in the request or create one and store
 * it in the request if not.</p>
 */
public class MappedCRUDAuthenticationInterceptor extends MappablePermissionsInterceptor {
    private static final PermissionsMapping CRUD_MAPPING = PermissionsMapping.builder()
            .defaultAllOf(Permission.Value.READ)
            .mapAllOf(HttpMethod.PUT.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.PATCH.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.POST.toString(), Permission.Value.CREATE)
            .mapAllOf(HttpMethod.DELETE.toString(), Permission.Value.DELETE)
            .build();

    /**
     * @param permissionKey      The expected permission key
     * @param ignoredHttpMethods An optional array of HTTP methods for which the interceptor
     *                           won't run
     */
    public MappedCRUDAuthenticationInterceptor(final Permission.Key permissionKey,
            final String... ignoredHttpMethods) {
        super(permissionKey, CRUD_MAPPING, ignoredHttpMethods);
    }

    /**
     * @param permissionKey        The expected permission key
     * @param ignoreAPIKeyRequests If true this interceptor will allow any API key traffic through.
     *                             Other specific API key checks (for elevated privileges etc)
     *                             should be applied to these routes to cover specific logic when
     *                             this is true.
     * @param ignoredHttpMethods   An optional array of HTTP methods for which the interceptor
     *                             won't run
     */
    public MappedCRUDAuthenticationInterceptor(final Permission.Key permissionKey,
            final boolean ignoreAPIKeyRequests, final String... ignoredHttpMethods) {
        super(permissionKey, ignoreAPIKeyRequests, CRUD_MAPPING, ignoredHttpMethods);
    }

}