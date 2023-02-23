package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import uk.gov.companieshouse.api.util.security.SecurityConstants;

public class UserAuthenticationInterceptor extends InternalUserInterceptor {

    private List<String> otherAllowedIdentityTypes;
    private List<String> externalMethods;

    public UserAuthenticationInterceptor(List<String> externalMethods, List<String> otherAllowedIdentityTypes) {
        this.otherAllowedIdentityTypes = otherAllowedIdentityTypes;
        this.externalMethods = externalMethods;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {   
        if (externalMethods.contains(request.getMethod())) {
            ArrayList<String> validTypes = new ArrayList<>(Arrays.asList(SecurityConstants.API_KEY_IDENTITY_TYPE));
            validTypes.addAll(otherAllowedIdentityTypes);
            return hasAuthorisedIdentity(request, response) && hasValidAuthorisedIdentityType(request, response, validTypes);
        } else {
            return super.preHandle(request, response, handler);
        }
    }
}