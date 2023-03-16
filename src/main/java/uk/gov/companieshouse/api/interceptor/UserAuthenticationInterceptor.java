package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

public class UserAuthenticationInterceptor extends HandlerInterceptorAdapter {

    private InternalUserInterceptor internalUserInterceptor;
    private List<String> otherAllowedIdentityTypes;
    private List<String> externalMethods;
    private Logger logger;

    @Autowired
    public UserAuthenticationInterceptor(List<String> externalMethods, List<String> otherAllowedIdentityTypes, InternalUserInterceptor internalUserInterceptor) {
        this.otherAllowedIdentityTypes = otherAllowedIdentityTypes;
        this.externalMethods = externalMethods;
        this.internalUserInterceptor = internalUserInterceptor;
        logger = LoggerFactory.getLogger(String.valueOf(UserAuthenticationInterceptor.class));
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        if (externalMethods.contains(request.getMethod())) {
            ArrayList<String> validTypes = new ArrayList<>(Arrays.asList(SecurityConstants.API_KEY_IDENTITY_TYPE));
            validTypes.addAll(otherAllowedIdentityTypes);
            return hasAuthorisedIdentity(request, response) && hasValidAuthorisedIdentityType(request, response, validTypes);
        } else {
            return internalUserInterceptor.preHandle(request, response, handler);
        }
    }

    private boolean hasAuthorisedIdentity(HttpServletRequest request, HttpServletResponse response) {
        final String authorisedUser = AuthorisationUtil.getAuthorisedIdentity(request); 
        if (authorisedUser == null) {
            logger.debugRequest(request, "no authorised identity", null);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }
        return true;
    }

    private boolean hasValidAuthorisedIdentityType(HttpServletRequest request, HttpServletResponse response,
            List<String> validIdentityTypes) {
        final String identityType = AuthorisationUtil.getAuthorisedIdentityType(request);
        if ( !validIdentityTypes.contains(identityType)) {
            logger.debugRequest(request, "invalid identity type [" + identityType + "]", null);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }
}