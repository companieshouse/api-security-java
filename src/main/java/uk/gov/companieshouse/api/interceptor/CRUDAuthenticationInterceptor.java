package uk.gov.companieshouse.api.interceptor;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Checks the request contains the relevant token permission value based on the
 * http method 
 * It will try to find a {@link TokenPermissions} object in the
 * request or create one and store it in the request if not
 */
public class CRUDAuthenticationInterceptor extends HandlerInterceptorAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(String.valueOf(CRUDAuthenticationInterceptor.class));

    @Value("${ENABLE_TOKEN_PERMISSION_AUTH:#{false}}")
    boolean enableTokenPermissionAuth;

    private final Permission.Key permissionKey;
    private final Set<String> ignoredHttpMethods;

    /**
     * 
     * @param permissionKey The expected permission key
     * @param ignoredHttpMethods An optional array of http methods for which the interceptor won't run
     */
    public CRUDAuthenticationInterceptor(Permission.Key permissionKey, String... ignoredHttpMethods) {
        this.permissionKey = permissionKey;
        this.ignoredHttpMethods = new HashSet<>(Arrays.asList(ignoredHttpMethods));
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws InvalidTokenPermissionException{
        if (ignoreRequest(request)) {
            return true;
        }

        final TokenPermissions tokenPermissions = getTokenPermissions(request);

        final String permissionValue = getValue(request);
        final boolean authorised = tokenPermissions.hasPermission(permissionKey, permissionValue);

        final Map<String, Object> debugMap = new HashMap<>();
        debugMap.put("request_method", request.getMethod());
        debugMap.put("authorised", authorised);
        debugMap.put("expected_permission", permissionKey + "=" + permissionValue);

        if (!authorised) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        LOGGER.debugRequest(request, "CRUDAuthenticationInterceptor handled request", debugMap);
        return authorised;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
            ModelAndView modelAndView) throws Exception {
        if (!ignoreRequest(request)) {
            // cleanup request to ensure it is never leaked into another request
            InterceptorHelper.storeTokenPermissionsInRequest(null, request);
        }
    }
    
    private boolean ignoreRequest(HttpServletRequest request) {
        return ignoredHttpMethods.contains(request.getMethod());
    }
    /**
     * Get the token permissions object from the request or create one (and store it
     * in the request) if there is not one
     * 
     * @param request
     * @return
     */
    private TokenPermissions getTokenPermissions(HttpServletRequest request) {
        // TokenPermissions could have been set up in the request by
        // TokenPermissionsInterceptor or another instance of this interceptor
        return getTokenPermissionsFromRequest(request).orElseGet(() -> {
            try {
                TokenPermissions tp = InterceptorHelper.readTokenPermissions(request, enableTokenPermissionAuth);
                InterceptorHelper.storeTokenPermissionsInRequest(tp, request);
                Map<String, Object> loggedData = new HashMap<>();
                loggedData.put("Feature flag ENABLE_TOKEN_PERMISSION_AUTH", enableTokenPermissionAuth);
                LOGGER.debug("Create TokenPermissions and store it in request", loggedData);
                return tp;
            } catch (InvalidTokenPermissionException e) {
                // Wrap into a runtime exception to fit the Supplier interface
                throw new IllegalStateException(e);
            }
        });
    }

    protected Optional<TokenPermissions> getTokenPermissionsFromRequest(HttpServletRequest request) {
        return AuthorisationUtil.getTokenPermissions(request);
    }

    private String getValue(HttpServletRequest request) {
        String method = request.getMethod();
        if (HttpMethod.PUT.matches(method) || HttpMethod.PATCH.matches(method)) {
            return Permission.Value.UPDATE;
        }
        if (HttpMethod.POST.matches(method)) {
            return Permission.Value.CREATE;
        }
        if (HttpMethod.DELETE.matches(method)) {
            return Permission.Value.DELETE;
        }
        return Permission.Value.READ;
    }

}