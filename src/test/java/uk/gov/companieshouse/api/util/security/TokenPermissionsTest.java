package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import uk.gov.companieshouse.api.util.security.Permission.Value;

class TokenPermissionsTest {

    private static final String AUTHORISED_TOKEN_PERMISSIONS = "company_number=00001234 company_transactions=read user_profile=read user_transactions=read,create,update company_auth_code=read,update,delete company_status=read,update,delete company_promise_to_file=update company_officers=delete,readprotected,update,create company_oe_annual_update=create";

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
    void hasCompanyNumberPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, "00001234"));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_NUMBER, "43210000"));
    }

    @Test
    void hasUserProfilePermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.READ));
        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.USER_PROFILE, Permission.Value.DELETE));
    }

    @Test
    void hasUserTransactionsPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.USER_TRANSACTIONS, Permission.Value.DELETE));
    }

    @Test
    void hasCompanyAuthCodePermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.UPDATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_AUTH_CODE, Permission.Value.DELETE));
    }

    @Test
    void hasCompanyStatusPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_STATUS, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_STATUS, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_STATUS, Permission.Value.UPDATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_STATUS, Permission.Value.DELETE));
    }

    @Test
    void hasCompanyTransactionsPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.CREATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.READ));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_TRANSACTIONS, Permission.Value.DELETE));
    }

    @Test
    void hasPromiseToFilesPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertFalse(permissions.hasPermission(Permission.Key.PROMISE_TO_FILE, Permission.Value.CREATE));
        assertFalse(permissions.hasPermission(Permission.Key.PROMISE_TO_FILE, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.PROMISE_TO_FILE, Permission.Value.UPDATE));
        assertFalse(permissions.hasPermission(Permission.Key.PROMISE_TO_FILE, Permission.Value.DELETE));
    }

    @Test
    void hasCompanyOfficersPermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_OFFICERS, Value.READ_PROTECTED));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_OFFICERS, Permission.Value.DELETE));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_OFFICERS, Permission.Value.READ));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_OFFICERS, Value.UPDATE));
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_OFFICERS, Value.CREATE));
    }

    @Test
    void hasOEUpdatePermissionKeysAndValues() throws InvalidTokenPermissionException {
        setupPermissionHeader(AUTHORISED_TOKEN_PERMISSIONS);
        assertTrue(permissions.hasPermission(Permission.Key.COMPANY_OE_UPDATE, Value.CREATE));
        assertFalse(permissions.hasPermission(Permission.Key.COMPANY_OE_UPDATE, Permission.Value.READ));
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
