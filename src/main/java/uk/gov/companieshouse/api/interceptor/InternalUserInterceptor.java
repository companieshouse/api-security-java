package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Pre handle method to authenticate the request before it reaches the controller by checking if
 * the CH API key is valid. The request is also checked to see if the user is in a role which can
 * make internal calls.
 */
@Component
public class InternalUserInterceptor extends HandlerInterceptorAdapter {
    
    private final Logger LOG;

    public InternalUserInterceptor() {
        LOG = LoggerFactory.getLogger(String.valueOf(InternalUserInterceptor.class));
    }

    public InternalUserInterceptor(String loggingNamespace) {
        LOG = LoggerFactory.getLogger(loggingNamespace);
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,  Object handler) throws IOException {
        if (hasAuthorisedIdentity(request, response) && hasValidAuthorisedIdentityType(
                    request, response, Arrays.asList(SecurityConstants.API_KEY_IDENTITY_TYPE))
                && hasInternalRole(request, response)) {
            LOG.debugRequest(request, "authorised as api key (internal user)", null);
            return true;
        } else {
            return false;
        }
    }

    public boolean hasAuthorisedIdentity(HttpServletRequest request, HttpServletResponse response) {
        final String authorisedUser = AuthorisationUtil.getAuthorisedIdentity(request); 
        if (authorisedUser == null) {
            LOG.debugRequest(request, "no authorised identity", null);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }
        return true;
    }

    public boolean hasValidAuthorisedIdentityType(HttpServletRequest request, HttpServletResponse response,
            List<String> validIdentityTypes) {
        final String identityType = AuthorisationUtil.getAuthorisedIdentityType(request);
        if ( !validIdentityTypes.contains(identityType)) {
            LOG.debugRequest(request, "invalid identity type [" + identityType + "]", null);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }

    public boolean hasInternalRole(HttpServletRequest request, HttpServletResponse response) {
        boolean hasInternalUserRole = AuthorisationUtil.hasInternalUserRole(request);
        if ( ! hasInternalUserRole) {
            LOG.debugRequest(request, "user does not have internal user privileges ", null);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        return true;
    }
}

