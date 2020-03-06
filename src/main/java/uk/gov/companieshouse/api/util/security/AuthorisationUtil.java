package uk.gov.companieshouse.api.util.security;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

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
    
    protected static String getAuthorisedTokenPermissions(HttpServletRequest request) {
        return RequestUtils.getRequestHeader(request, EricConstants.ERIC_AUTHORISED_TOKEN_PERMISSIONS);
    }
    
    public static boolean hasInternalUserRole(HttpServletRequest request) {
        return SecurityConstants.INTERNAL_USER_ROLE.equals(getAuthorisedKeyRoles(request));
    }
    
    public static Optional<TokenPermissions> getTokenPermissions(HttpServletRequest request) {
        return Optional.ofNullable((TokenPermissions) request.getAttribute(SecurityConstants.TOKEN_PERMISSION_REQUEST_KEY));
    }
}
