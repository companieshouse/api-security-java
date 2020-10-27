package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.Permission.Value;
import uk.gov.companieshouse.api.util.security.TokenPermissions;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
public class CRUDAuthenticationInterceptorTest {
    private static final Object HANDLER = null;

    private final Permission.Key permissionKey = Permission.Key.USER_PROFILE;

    @Spy
    private CRUDAuthenticationInterceptor interceptor = new CRUDAuthenticationInterceptor(permissionKey);

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private TokenPermissions tokenPermissions;

    @Test
    @DisplayName("Test preHandle when TokenPermissions is not present in request")
    void preHandleMissingTokenPermissions() throws Exception {
        assertThrows(IllegalStateException.class, () -> interceptor.preHandle(request, response, HANDLER));
    }

    @Test
    @DisplayName("Tests the interceptor with a valid POST request")
    void preHandleAuthorisedPost() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("POST");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.CREATE)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid POST request")
    void preHandleUnauthorisedPost() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("POST");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.CREATE)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid GET request")
    void preHandleAuthorisedGet() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("GET");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid GET request")
    void preHandleUnauthorisedGet() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("GET");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid PUT request")
    void preHandleAuthorisedPut() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("PUT");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.UPDATE)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid PUT request")
    void preHandleUnauthorisedPut() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("PUT");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.UPDATE)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid DELETE request")
    void preHandleAuthorisedDelete() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("DELETE");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.DELETE)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid DELETE request")
    void preHandleUnauthorisedDelete() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("DELETE");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.DELETE)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid PATCH request")
    void preHandleAuthorisedPatch() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("PATCH");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.UPDATE)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid PATCH request")
    void preHandleUnauthorisedPatch() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("PATCH");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.UPDATE)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid HEAD request")
    void preHandleAuthorisedHead() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("HEAD");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid HEAD request")
    void preHandleUnauthorisedHead() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("HEAD");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid CONNECT request")
    void preHandleAuthorisedConnect() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("CONNECT");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid CONNECT request")
    void preHandleUnauthorisedConnect() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("CONNECT");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid OPTIONS request")
    void preHandleAuthorisedOptions() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("OPTIONS");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid OPTIONS request")
    void preHandleUnauthorisedOptions() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("OPTIONS");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with a valid TRACE request")
    void preHandleAuthorisedTrace() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("TRACE");
        final boolean authorised = true;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertTrue(interceptor.preHandle(request, response, HANDLER));
        verifyNoInteractions(response);
        verifyNoMoreInteractions(tokenPermissions);
    }

    @Test
    @DisplayName("Tests the interceptor with an invalid TRACE request")
    void preHandleUnauthorisedTrace() throws InvalidTokenPermissionException {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn("TRACE");
        final boolean authorised = false;
        when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(authorised);

        assertFalse(interceptor.preHandle(request, response, HANDLER));
        verify(response).setStatus(401);
        verifyNoMoreInteractions(tokenPermissions);
    }
    private void setupTokenPermissions() {
        doReturn(Optional.of(tokenPermissions)).when(interceptor).getTokenPermissions(request);
    }
}
