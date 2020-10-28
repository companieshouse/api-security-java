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
import uk.gov.companieshouse.api.util.security.TokenPermissions;
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

        TokenPermissions tokenPermissions = InterceptorHelper.readTokenPermissions(request, enableTokenPermissionAuth);
        InterceptorHelper.storeTokenPermissionsInRequest(tokenPermissions, request);
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
            ModelAndView modelAndView) throws Exception {
        // cleanup request to ensure it is never leaked into another request
        InterceptorHelper.storeTokenPermissionsInRequest(null, request);
    }

}