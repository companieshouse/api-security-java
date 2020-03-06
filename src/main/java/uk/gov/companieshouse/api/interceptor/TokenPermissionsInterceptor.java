package uk.gov.companieshouse.api.interceptor;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Creates a TokenPermissions object and sets it into the request. 
 * It can then be read by using {@link AuthorisationUtil.getTokenPermissions(request)}
 */
@Component
public class TokenPermissionsInterceptor extends HandlerInterceptorAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(String.valueOf(TokenPermissionsInterceptor.class));

    @Value("${ENABLE_TOKEN_PERMISSION_AUTH:#{false}}")
    boolean enableTokenPermissionAuth;
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws InvalidTokenPermissionException {
        Map<String, Object> loggedData = new HashMap<>();
        loggedData.put("Feature flag ENABLE_TOKEN_PERMISSION_AUTH", enableTokenPermissionAuth);
        LOGGER.debug("Create TokenPermissions and store it in request", loggedData);
        final TokenPermissions tokenPermissions = new TokenPermissionsImpl(request);
        if (enableTokenPermissionAuth) {
            request.setAttribute(SecurityConstants.TOKEN_PERMISSION_REQUEST_KEY, tokenPermissions);
        } else {
            // We behave as if we had all permissions except for the company number
            TokenPermissions tp = (k, v) -> {
                if (k.equals(Permission.Key.COMPANY_NUMBER)) {
                    return tokenPermissions.hasPermission(k, v);
                } else {
                    return true;
                }
            };
            request.setAttribute(SecurityConstants.TOKEN_PERMISSION_REQUEST_KEY, tp);
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
            ModelAndView modelAndView) throws Exception {
        // cleanup request to ensure it is never leaked into another request
        request.setAttribute(SecurityConstants.TOKEN_PERMISSION_REQUEST_KEY, null);
    }

    /**
     * Set the feature flag: if on (true) this interceptor will create a token
     * permissions object which will check the relevant eric header to authorise via
     * token permissions. If off (false), the object stored in the session will only
     * check the header for the company number permission and authorise any other
     * 
     * @param enable
     */
    public void setEnableTokenPermission(boolean enable) {
        enableTokenPermissionAuth = enable;
    }
    
    /**
     * Read the feature flag: if on (true) this interceptor will create a token
     * permissions object which will check the relevant eric header to authorise via
     * token permissions. If off (false), the object stored in the session will only
     * check the header for the company number permission and authorise any other
     * 
     * @return True if the feature flag is on. False if it is off
     */
    public boolean isEnableTokenPermission() {
        return enableTokenPermissionAuth;
    }
}