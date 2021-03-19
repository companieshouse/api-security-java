package uk.gov.companieshouse.api.interceptor;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws InvalidTokenPermissionException {
        Map<String, Object> loggedData = new HashMap<>();
        LOGGER.debugRequest(request, "Create TokenPermissions and store it in request", loggedData);

        TokenPermissions tokenPermissions = readTokenPermissions(request);
        InterceptorHelper.storeTokenPermissionsInRequest(tokenPermissions, request);
        return true;
    }

    TokenPermissions readTokenPermissions(HttpServletRequest request) throws InvalidTokenPermissionException {
        return InterceptorHelper.readTokenPermissions(request);
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
            ModelAndView modelAndView) throws Exception {
        // cleanup request to ensure it is never leaked into another request
        InterceptorHelper.storeTokenPermissionsInRequest(null, request);
    }

}