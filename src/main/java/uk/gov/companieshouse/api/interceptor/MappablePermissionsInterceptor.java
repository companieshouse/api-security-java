package uk.gov.companieshouse.api.interceptor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Checks the request contains the relevant token permission value based on the
 * HTTP method.
 * It will try to find any one of the required permissions are present in the
 * {@link TokenPermissions} object in the request. If not, it will create that object and store
 * it in the request.
 */
public class MappablePermissionsInterceptor implements HandlerInterceptor {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(String.valueOf(MappablePermissionsInterceptor.class));

    private final Permission.Key permissionKey;
    private final boolean ignoreAPIKeyRequests;
    private final Set<String> ignoredHttpMethods;
    private final PermissionsMapping permissionsMapping;

    /**
     * @param permissionKey      The expected permission key
     * @param permissionsMapping The mapping from HTTP method to allowed Permission.Value's
     *                           String constant.
     * @param ignoredHttpMethods An optional array of HTTP methods for which the interceptor
     *                           won't run
     */
    public MappablePermissionsInterceptor(final Permission.Key permissionKey,
            final PermissionsMapping permissionsMapping, final String... ignoredHttpMethods) {
        this(permissionKey, false, permissionsMapping, ignoredHttpMethods);
    }

    /**
     * @param permissionKey        The expected permission key
     * @param ignoreAPIKeyRequests If true this interceptor will allow any API key traffic through.
     *                             Other specific API key checks (for elevated privileges etc.)
     *                             should be applied to these routes to cover specific logic when
     *                             this is true.
     * @param permissionsMapping   The mapping from HTTP method to allowed permissions.
     * @param ignoredHttpMethods   An optional array of HTTP methods for which the interceptor
     *                             won't run
     */
    public MappablePermissionsInterceptor(final Permission.Key permissionKey,
            final boolean ignoreAPIKeyRequests, final PermissionsMapping permissionsMapping,
            final String... ignoredHttpMethods) {
        this.permissionKey = permissionKey;
        this.ignoreAPIKeyRequests = ignoreAPIKeyRequests;
        this.permissionsMapping = permissionsMapping;
        this.ignoredHttpMethods = new HashSet<>(Arrays.asList(ignoredHttpMethods));
    }

    @Override
    public boolean preHandle(@NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response, @NonNull final Object handler) {
        if (ignoreRequest(request)) {
            return true;
        }

        final TokenPermissions tokenPermissions = getTokenPermissions(request);
        final Set<String> expected = permissionsMapping.apply(request.getMethod());
        final boolean authorised = expected.isEmpty() || expected.stream()
                .anyMatch(p -> tokenPermissions.hasPermission(permissionKey, p));

        if (!authorised) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        final Map<String, Object> debugMap = new HashMap<>();

        debugMap.put("request_method", request.getMethod());
        debugMap.put("authorised", authorised);
        debugMap.put("expected_permissions", permissionKey + "=" + expected);
        LOGGER.debugRequest(request,
                MappablePermissionsInterceptor.class.getSimpleName() + " handled request",
                debugMap);

        return authorised;
    }

    @Override
    public void postHandle(@NonNull final HttpServletRequest request,
            @NonNull final HttpServletResponse response, @NonNull final Object handler,
            @Nullable final ModelAndView modelAndView) {
        if (!ignoreRequest(request)) {
            // cleanup request to ensure it is never leaked into another request
            InterceptorHelper.storeTokenPermissionsInRequest(null, request);
        }
    }

    private boolean ignoreRequest(final HttpServletRequest request) {
        return ignoredHttpMethods.contains(request.getMethod()) || (this.ignoreAPIKeyRequests
                && SecurityConstants.API_KEY_IDENTITY_TYPE.equals(
                AuthorisationUtil.getAuthorisedIdentityType(request)));
    }

    /**
     * Get the token permissions object from the request or create one (and store it
     * in the request) if there is not one
     *
     * @param request the HTTP request
     * @return the token permissions stored
     */
    private TokenPermissions getTokenPermissions(final HttpServletRequest request) {
        // TokenPermissions could have been set up in the request by
        // TokenPermissionsInterceptor or another instance of this interceptor
        return getTokenPermissionsFromRequest(request).orElseGet(() -> {
            try {
                final TokenPermissions tp = InterceptorHelper.readTokenPermissions(request);
                InterceptorHelper.storeTokenPermissionsInRequest(tp, request);
                final Map<String, Object> loggedData = new HashMap<>();
                LOGGER.debugRequest(request, "Create TokenPermissions and store it in request",
                        loggedData);
                return tp;
            }
            catch (final InvalidTokenPermissionException e) {
                // Wrap into a runtime exception to fit the Supplier interface
                throw new IllegalStateException(e);
            }
        });
    }

    protected Optional<TokenPermissions> getTokenPermissionsFromRequest(
            final HttpServletRequest request) {
        return AuthorisationUtil.getTokenPermissions(request);
    }

}