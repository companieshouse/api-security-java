package uk.gov.companieshouse.api.interceptor;

import javax.servlet.http.HttpServletRequest;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;

class InterceptorHelper {

    private InterceptorHelper() {
        // Private constructor for utility class
    }

    /**
     * Parse the token permissions object from the request and return a
     * {@link TokenPermissions} object
     * 
     * @param request                   The HTTP request
     * @param enableTokenPermissionAuth Feature flag: when true, it will create a
     *                                  token permissions object which will check
     *                                  the relevant eric header to authorise via
     *                                  token permissions. If false, the object
     *                                  stored in the session will only check the
     *                                  header for the company number permission and
     *                                  authorise any other
     * @return A {@link TokenPermissions} object containing the permissions for the
     *         request
     * @throws InvalidTokenPermissionException If there is a problem parsing the
     *                                         request
     */
    static TokenPermissions readTokenPermissions(HttpServletRequest request, boolean enableTokenPermissionAuth)
            throws InvalidTokenPermissionException {
        final TokenPermissions tokenPermissions = new TokenPermissionsImpl(request);
        if (enableTokenPermissionAuth) {
            return tokenPermissions;
        } else {
            // We behave as if we had all permissions except for the company number
            return (k, v) -> {
                if (k.equals(Permission.Key.COMPANY_NUMBER)) {
                    return tokenPermissions.hasPermission(k, v);
                } else {
                    return true;
                }
            };
        }
    }

    /**
     * Store the given TokenPermissions object in the given request
     * 
     * @param tokenPermissions It can be null if we want to remove the existing one
     * @param request
     */
    static void storeTokenPermissionsInRequest(TokenPermissions tokenPermissions, HttpServletRequest request) {
        request.setAttribute(SecurityConstants.TOKEN_PERMISSION_REQUEST_KEY, tokenPermissions);
    }
}
