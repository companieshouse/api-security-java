package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;
import uk.gov.companieshouse.api.util.security.Permission.Key;
import uk.gov.companieshouse.api.util.security.Permission.Value;

@ExtendWith(MockitoExtension.class)
public class InterceptorHelperTest {

    @Test
    @DisplayName("Test readTokenPermissions")
    void readTokenPermissions() throws InvalidTokenPermissionException {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        when(request.getHeader("ERIC-Authorised-Token-Permissions"))
                .thenReturn("company_number=00001234 user_profile=read");

        TokenPermissions tp = InterceptorHelper.readTokenPermissions(request);

        assertNotNull(tp);
        assertTrue(tp instanceof TokenPermissionsImpl);
        assertTrue(tp.hasPermission(Key.COMPANY_NUMBER, "00001234"));
        assertFalse(tp.hasPermission(Key.COMPANY_NUMBER, "88888888"));
        assertTrue(tp.hasPermission(Key.USER_PROFILE, Value.READ));
        assertFalse(tp.hasPermission(Key.USER_PROFILE, Value.UPDATE));
        assertFalse(tp.hasPermission(Key.USER_PROFILE, Value.CREATE));
        assertFalse(tp.hasPermission(Key.USER_PROFILE, Value.DELETE));
    }

    @Test
    @DisplayName("Test storeTokenPermissionsInRequest with valid object")
    void storeTokenPermissionsInRequest() {
        TokenPermissions tokenPermissions = Mockito.mock(TokenPermissions.class);
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        InterceptorHelper.storeTokenPermissionsInRequest(tokenPermissions, request);

        verify(request).setAttribute("token_permissions", tokenPermissions);
        verifyNoMoreInteractions(request);
        verifyNoInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Test storeTokenPermissionsInRequest with null")
    void storeTokenPermissionsInRequestNull() {
        TokenPermissions tokenPermissions = null;
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        InterceptorHelper.storeTokenPermissionsInRequest(tokenPermissions, request);

        verify(request).setAttribute("token_permissions", tokenPermissions);
        verifyNoMoreInteractions(request);
    }
}
