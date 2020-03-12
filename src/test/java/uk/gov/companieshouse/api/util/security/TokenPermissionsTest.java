package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class TokenPermissionsTest {
    
    private static final String AUTHORISED_TOKEN_PERMISSIONS = "company_number=00001234 company_transactions=read user_profile=read user_transactions=read,create,update company_auth_code=read,update,delete";

    TokenPermissionsImpl permissions;

    @Test
    void hasSingleCompanyNumberPermissionKeyAndValue() throws InvalidTokenPermissionException {
        setupPermissionHeader("company_number=12345678");
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, "12345678"));
    }

    @Test
    void hasSingleUserProfilePermissionKeyAndValue() throws InvalidTokenPermissionException {
        setupPermissionHeader("user_profile=read");
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.READ));
    }

    @Test
    void hasCRUDUserProfilePermissionKeyAndValue() throws InvalidTokenPermissionException {
        setupPermissionHeader("user_profile=create,read,update,delete");
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.UPDATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.DELETE));
    }

    @Test
    void hasPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);

        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, "00001234"));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, "43210000"));

        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.READ));
        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.DELETE));

        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.DELETE));

        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.DELETE));

        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.READ));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.DELETE));
    }

    @Test
    void hasPermissionKeyNotValue() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, "missing"));
    }

    @Test
    void hasPermissionNoKey() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_ROA, Permission.Value.DELETE));
    }
    
    @Test
    void hasPermissionNullValue() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, null));
    }

    @Test
    void hasPermissionMissingHeader() throws InvalidTokenPermissionException {
        setupPermissionHeader(null);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }

    @Test
    void hasPermissionEmptyHeader() throws InvalidTokenPermissionException {
        setupPermissionHeader("");
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
    }

    @Test
    void invalidTokenPermissions() {
        assertThrows(InvalidTokenPermissionException.class, () -> setupPermissionHeader(
                "user_profile=read user_transactions= company_auth_code=read,update,delete"));
    }

    private void setupPermissionHeader(String authorisedTokenPermissins) throws InvalidTokenPermissionException {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(authorisedTokenPermissins);

        permissions = new TokenPermissionsImpl(request);
    }
}
