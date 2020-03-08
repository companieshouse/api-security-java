package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.Permission.Key;
import uk.gov.companieshouse.api.util.security.Permission.Value;
import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class TokenPermissionsInterceptorTest {

    private static final String AUTHORISED_TOKEN_PERMISSIONS = "company_number=00001234 user_profile=read user_transactions=read,create,update company_auth_code=read,update,delete";
    private static final Object HANDLER = null;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Captor
    private ArgumentCaptor<TokenPermissions> tokenPermissionsCaptor;

    private TokenPermissionsInterceptor interceptor = new TokenPermissionsInterceptor();

    @Test
    @DisplayName("Test that the preHandle method sets a TokenPermissions object in the request")
    public void preHandle() throws Exception {
        interceptor.enableTokenPermissionAuth = true;
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(AUTHORISED_TOKEN_PERMISSIONS);

        assertTrue(interceptor.preHandle(request, response, HANDLER));

        verify(request).setAttribute(eq("token_permissions"), tokenPermissionsCaptor.capture());

        TokenPermissions tokenPermissions = tokenPermissionsCaptor.getValue();

        assertNotNull(tokenPermissions);
        assertTrue(tokenPermissions instanceof TokenPermissionsImpl);
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_NUMBER, "00001234"));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_NUMBER, "88888888"));
        assertTrue(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.READ));
        assertFalse(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.DELETE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.READ));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.DELETE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.READ));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.DELETE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.READ));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.DELETE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.READ));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.UPDATE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.CREATE));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.DELETE));
    }

    @Test
    @DisplayName("Test that the preHandle method throws an exception when the token permission string is invalid")
    public void preHandleThrowsException() throws Exception {
        interceptor.enableTokenPermissionAuth = true;
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn("invalid=");

        assertThrows(InvalidTokenPermissionException.class, () -> interceptor.preHandle(request, response, HANDLER));
    }

    @Test
    @DisplayName("Test that the preHandle method sets a TokenPermissions object in the request which gives permission to all keys apart from company number")
    public void preHandleFeatureFlagOff() throws Exception {
        interceptor.enableTokenPermissionAuth = false;
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(AUTHORISED_TOKEN_PERMISSIONS);

        assertTrue(interceptor.preHandle(request, response, HANDLER));

        verify(request).setAttribute(eq("token_permissions"), tokenPermissionsCaptor.capture());

        TokenPermissions tokenPermissions = tokenPermissionsCaptor.getValue();

        assertNotNull(tokenPermissions);
        assertFalse(tokenPermissions instanceof TokenPermissionsImpl);
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_NUMBER, "00001234"));
        assertFalse(tokenPermissions.hasPermission(Key.COMPANY_NUMBER, "88888888"));
        assertTrue(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_PROFILE, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_TRANSACTIONS, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_AUTH_CODE, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ACCOUNTS, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.USER_APPLICATIONS, Value.DELETE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.READ));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.UPDATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.CREATE));
        assertTrue(tokenPermissions.hasPermission(Key.COMPANY_ROA, Value.DELETE));
    }

    @Test
    @DisplayName("Test that the postHandle method removes the TokenPermissions object from the request")
    public void postHandle() throws Exception {
        interceptor.enableTokenPermissionAuth = true;

        interceptor.postHandle(request, response, HANDLER, null);

        verify(request).setAttribute("token_permissions", null);
    }
}
