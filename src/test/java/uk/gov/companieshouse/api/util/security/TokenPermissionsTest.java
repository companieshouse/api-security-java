package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class TokenPermissionsTest {
    
    private static final String AUTHORISED_TOKEN_PERMISSIONS = "user_profile=read user_transactions=read,create,update company_auth_code=read,update,delete";

    TokenPermissions permissions;

    @Test
    void hasPermissionKeyAndValue() {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }

    @Test
    void hasPermissionKeyNotValue() {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, "missing"));
    }

    @Test
    void hasPermissionNoKey() {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_ROA, Permission.Value.DELETE));
    }

    @Test
    void hasPermissionMissingHeader() {
        setupPermissionHeader(null);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }
    
    @Test
    void hasPermissionEmptyHeader() {
        setupPermissionHeader("");
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }
    
    @Test
    void hasPermissionBlankHeader() {
        setupPermissionHeader("   ");
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }
    
    @Test
    void hasPermissionInvalidPairRequestedKey() {
        setupPermissionHeader("user_profile=read user_transactions= company_auth_code=read,update,delete");
        assertFalse(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.DELETE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.DELETE));
    }
    
    @Test
    void hasPermissionInvalidPairDifferentKey() {
        setupPermissionHeader("user_profile=read user_transactions= company_auth_code=read,update,delete");
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.DELETE));
    }
    
    private void setupPermissionHeader(String authorisedTokenPermissins) {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(authorisedTokenPermissins);

        permissions = new TokenPermissions(request);
    }
}
