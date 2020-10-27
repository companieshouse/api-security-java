package uk.gov.companieshouse.api.interceptor;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
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
 * Prerequisite: the {@link TokenPermissionsInterceptor} must have
 * run previously so that a {@link TokenPermissions} object is stored in the request
 */
public class CRUDAuthenticationInterceptor extends HandlerInterceptorAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(String.valueOf(CRUDAuthenticationInterceptor.class));
    
    private final Permission.Key permissionKey;
    
    public CRUDAuthenticationInterceptor(Permission.Key permissionKey) {
        this.permissionKey = permissionKey;
    }
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws InvalidTokenPermissionException {
        // TokenPermissions should have been set up in the request by TokenPermissionsInterceptor
        final TokenPermissions tokenPermissions = getTokenPermissions(request)
                .orElseThrow(() -> new IllegalStateException("TokenPermissions object not present in request"));

        String permissionValue = getValue(request);
        boolean authorised = tokenPermissions.hasPermission(permissionKey, permissionValue);

        final Map<String, Object> debugMap = new HashMap<>();
        debugMap.put("request_method", request.getMethod());
        debugMap.put("authorised", authorised);
        debugMap.put("expected_permission", permissionKey + "=" + permissionValue);

        if (!authorised) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        LOGGER.debugRequest(request, "CRUDAuthenticationInterceptor ran", debugMap);
        return authorised;
    }

    protected Optional<TokenPermissions> getTokenPermissions(HttpServletRequest request) {
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