package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Pre handle method to authenticate the request before it reaches the controller by checking if
 * the CH API key is valid. The request is also checked to see if the user is in a role which can
 * make internal calls.
 */
@Component
public class InternalUserInterceptor extends HandlerInterceptorAdapter {
    
    private static final Logger LOG = LoggerFactory.getLogger(String.valueOf(InternalUserInterceptor.class));

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,  Object handler) throws IOException {   
        
        final String authorisedUser = AuthorisationUtil.getAuthorisedIdentity(request); 
        if (authorisedUser == null) {
            LOG.debugRequest(request, "no authorised identity", null);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        final String identityType = AuthorisationUtil.getAuthorisedIdentityType(request);
        if ( ! StringUtils.equals(identityType, EricConstants.API_KEY_IDENTITY_TYPE)) {
            LOG.debugRequest(request, "invalid identity type [" + identityType + "]", null);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        
        boolean hasInternalUserRole = AuthorisationUtil.hasInternalUserRole(request);
        if ( ! hasInternalUserRole) {
            LOG.debugRequest(request, "user does not have internal user privileges ", null);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
        
        LOG.debugRequest(request, "authorised as api key (internal user)", null);
        return true;
    }

}

