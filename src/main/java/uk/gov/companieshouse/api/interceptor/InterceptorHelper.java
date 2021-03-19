package uk.gov.companieshouse.api.interceptor;

import javax.servlet.http.HttpServletRequest;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
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
     * @param request The HTTP request
     * @return A {@link TokenPermissions} object containing the permissions for the
     *         request
     * @throws InvalidTokenPermissionException If there is a problem parsing the
     *                                         request
     */
    static TokenPermissions readTokenPermissions(HttpServletRequest request) throws InvalidTokenPermissionException {
        return new TokenPermissionsImpl(request);
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
