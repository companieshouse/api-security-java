package uk.gov.companieshouse.api.util.security;

import javax.servlet.http.HttpServletRequest;

import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.api.util.security.RequestUtils;

public final class AuthorisationUtil {
    private AuthorisationUtil() {}
    
    public static String getAuthorisedIdentity(HttpServletRequest request) {
        return RequestUtils.getRequestHeader(request, EricConstants.ERIC_IDENTITY);
    }

    public static String getAuthorisedIdentityType(HttpServletRequest request) {
        return RequestUtils.getRequestHeader(request, EricConstants.ERIC_IDENTITY_TYPE);
    }
    
    public static String getAuthorisedKeyRoles(HttpServletRequest request) {
        return RequestUtils.getRequestHeader(request, EricConstants.ERIC_AUTHORISED_KEY_ROLES);
    }
    
    public static boolean hasInternalUserRole(HttpServletRequest request) {
        return EricConstants.INTERNAL_USER_ROLE.equals(getAuthorisedKeyRoles(request));
    }
}
