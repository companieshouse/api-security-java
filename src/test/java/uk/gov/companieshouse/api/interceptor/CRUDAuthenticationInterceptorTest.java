package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.TestPropertySource;

import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.api.util.security.InvalidTokenPermissionException;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.Permission.Value;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class CRUDAuthenticationInterceptorTest {
    private static final Object HANDLER = null;

    private final Permission.Key permissionKey = Permission.Key.USER_PROFILE;
    private final Permission.Key otherPermissionKey = Permission.Key.COMPANY_ACCOUNTS;

    @Spy
    private CRUDAuthenticationInterceptor interceptor = new CRUDAuthenticationInterceptor(permissionKey, "IGNORED",
            "OTHER");

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private TokenPermissions tokenPermissions;

    @Captor
    private ArgumentCaptor<TokenPermissions> tokenPermissionsCaptor;

    @Test
    @DisplayName("Test preHandle when TokenPermissions is not present in request and the header is invalid")
    void preHandleMissingTokenPermissionsInvalidHeader() throws Exception {
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn("invalid");

        assertThrows(IllegalStateException.class, () -> interceptor.preHandle(request, response, HANDLER));
    }

    @Test
    @DisplayName("Test preHandle when TokenPermissions is not present in request")
    void preHandleMissingTokenPermissions() throws Exception {
        final String permissionsHeader = "company_number=00001234 " + permissionKey + "=create";
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(permissionsHeader);

        when(request.getMethod()).thenReturn("POST");

        assertTrue(interceptor.preHandle(request, response, HANDLER));

        verifyNoInteractions(response);
        verify(request).setAttribute(eq("token_permissions"), tokenPermissionsCaptor.capture());
        TokenPermissions tokenPermissions = tokenPermissionsCaptor.getValue();

        assertNotNull(tokenPermissions);
        assertTrue(tokenPermissions instanceof TokenPermissionsImpl);
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

    @Test
    @DisplayName("Test that the preHandle method does nothing when the HTTP method is ignored")
    void preHandleIgnoreRequest() throws Exception {
        when(request.getMethod()).thenReturn("OTHER");

        assertTrue(interceptor.preHandle(request, response, HANDLER));

        verifyNoMoreInteractions(request);
    }

    @Test
    @DisplayName("Test that the postHandle method removes the TokenPermissions object from the request")
    void postHandle() throws Exception {
        interceptor.postHandle(request, response, HANDLER, null);

        verify(request).setAttribute("token_permissions", null);
    }

    @Test
    @DisplayName("Test that the postHandle method does nothing when the HTTP method is ignored")
    void postHandleIgnoredMethod() throws Exception {
        when(request.getMethod()).thenReturn("IGNORED");

        interceptor.postHandle(request, response, HANDLER, null);

        verify(interceptor, never()).getTokenPermissionsFromRequest(request);
        verifyNoMoreInteractions(request);
    }

    @Test
    @DisplayName("Test that the ignoreAPIKeyRequests flag ignores API key request")
    void ignoreAPIKeyRequestsGetRequest() throws Exception {
        // custom interceptor with ignore api key flag set
        CRUDAuthenticationInterceptor customInterceptor = new CRUDAuthenticationInterceptor(permissionKey, true);
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn(SecurityConstants.API_KEY_IDENTITY_TYPE);

        assertTrue(customInterceptor.preHandle(request, response, HANDLER));

        verifyNoMoreInteractions(request);
    }

    @Nested
    class MultiplePermissionKeysTests {
        private CRUDAuthenticationInterceptor spyInterceptor;
        @BeforeEach
        void setup() {
            spyInterceptor = org.mockito.Mockito.spy(
                    new CRUDAuthenticationInterceptor(Arrays.asList(permissionKey, otherPermissionKey)));
            doReturn(Optional.of(tokenPermissions)).when(spyInterceptor).getTokenPermissionsFromRequest(request);
            when(request.getMethod()).thenReturn("GET");
            }

        @Test
        @DisplayName("Test multiple permission keys: all are granted allows access")
        void preHandleMultiplePermissionKeys_allAuthorised() throws Exception {

            when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(true);
            when(tokenPermissions.hasPermission(otherPermissionKey, Value.READ)).thenReturn(true);

            assertTrue(spyInterceptor.preHandle(request, response, HANDLER));
            verifyNoInteractions(response);
            verifyNoMoreInteractions(tokenPermissions);
        }

        @CsvSource({
                "true, false",
                "false, true"
        })
        @ParameterizedTest
        @DisplayName("Test multiple permission keys: at least one granted allows access")
        void preHandleMultiplePermissionKeys_anyAuthorised(boolean firstPermission, boolean secondPermission)
                throws Exception {

            when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(firstPermission);
            when(tokenPermissions.hasPermission(otherPermissionKey, Value.READ)).thenReturn(secondPermission);

            assertTrue(spyInterceptor.preHandle(request, response, HANDLER));
            verifyNoInteractions(response);
            verifyNoMoreInteractions(tokenPermissions);
        }

        @Test
        @DisplayName("Test multiple permission keys: none granted denies access")
        void preHandleMultiplePermissionKeys_noneAuthorised() throws Exception {

            when(tokenPermissions.hasPermission(permissionKey, Value.READ)).thenReturn(false);
            when(tokenPermissions.hasPermission(otherPermissionKey, Value.READ)).thenReturn(false);

            assertFalse(spyInterceptor.preHandle(request, response, HANDLER));
            verify(response).setStatus(401);
            verifyNoMoreInteractions(tokenPermissions);
        }
    }

    private void setupTokenPermissions() {
        doReturn(Optional.of(tokenPermissions)).when(interceptor).getTokenPermissionsFromRequest(request);
    }
}
