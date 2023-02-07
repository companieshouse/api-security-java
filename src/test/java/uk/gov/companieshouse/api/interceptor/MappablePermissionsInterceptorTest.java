package uk.gov.companieshouse.api.interceptor;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isA;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.SecurityConstants;
import uk.gov.companieshouse.api.util.security.TokenPermissions;
import uk.gov.companieshouse.api.util.security.TokenPermissionsImpl;

@ExtendWith(MockitoExtension.class)
class MappablePermissionsInterceptorTest {
    private static final Object HANDLER = new Object();
    private static final Permission.Key USER_PROFILE_KEY = Permission.Key.USER_PROFILE;
    private static final PermissionsMapping EXPECTED_MAPPING = PermissionsMapping.builder()
            .defaultAllOf(Permission.Value.READ)
            .mapAllOf(HttpMethod.PUT.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.PATCH.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.POST.toString(), Permission.Value.CREATE, Permission.Value.READ)
            .build();


    @Spy
    private MappablePermissionsInterceptor testInterceptor =
            new MappablePermissionsInterceptor(USER_PROFILE_KEY, EXPECTED_MAPPING, "IGNORED",
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
    @DisplayName("constructor with ignore API key")
    void constructorWithIgnoreApiKey() {
        final MappablePermissionsInterceptor interceptor =
                new MappablePermissionsInterceptor(USER_PROFILE_KEY, true, EXPECTED_MAPPING);

        assertThat(interceptor.getTokenPermissionsFromRequest(request), is(Optional.empty()));

    }

    @Test
    @DisplayName("preHandle when TokenPermissions is not present in request and the header is "
            + "invalid")
    void preHandlePermissionNotRequestedAndHeaderInvalid() {
        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn("invalid");

        assertThrows(IllegalStateException.class,
                () -> testInterceptor.preHandle(request, response, HANDLER));
    }

    @Test
    @DisplayName("preHandle when all required TokenPermission not present in request")
    void preHandleMissingTokenSinglePermission() {
        final String permissionsHeader = "company_number=00001234 " + USER_PROFILE_KEY + "=create";

        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(permissionsHeader);
        when(request.getMethod()).thenReturn("POST");

        assertThat(testInterceptor.preHandle(request, response, HANDLER), is(false));

        verify(request).setAttribute(eq("token_permissions"), tokenPermissionsCaptor.capture());
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final TokenPermissions tokenPermissions = tokenPermissionsCaptor.getValue();

        assertThat(tokenPermissions, isA(TokenPermissionsImpl.class));

    }

    @Test
    @DisplayName("preHandle when multiple required TokenPermission are all present in request")
    void preHandleMissingTokenMultiplePermission() {
        final String permissionsHeader =
                "company_number=00001234 " + USER_PROFILE_KEY + "=create,read";

        when(request.getHeader("ERIC-Authorised-Token-Permissions")).thenReturn(permissionsHeader);
        when(request.getMethod()).thenReturn("POST");

        assertThat(testInterceptor.preHandle(request, response, HANDLER), is(true));

        verifyNoInteractions(response);
        verify(request).setAttribute(eq("token_permissions"), tokenPermissionsCaptor.capture());

        final TokenPermissions tokenPermissions = tokenPermissionsCaptor.getValue();

        assertThat(tokenPermissions, isA(TokenPermissionsImpl.class));
    }

    @ParameterizedTest(name = "{index}: preHandle with a {0} request with validity {2}")
    @MethodSource({"providePermissions"})
    void preHandleAuthorisedValidity(final String httpMethod, final String[] requiredPermissions,
            final boolean isValid) {
        setupTokenPermissions();
        when(request.getMethod()).thenReturn(httpMethod);

        for (int i = 0; i < requiredPermissions.length; i++) {
            final String permission = requiredPermissions[i];
            // To test short-circuit evaluation, set only last to isValid, all others to TRUE
            when(tokenPermissions.hasPermission(USER_PROFILE_KEY, permission)).thenReturn(
                    i != requiredPermissions.length - 1 || isValid);
        }

        assertThat(testInterceptor.preHandle(request, response, HANDLER), is(isValid));
        if (isValid) {
            verifyNoInteractions(response);
        }
        else {
            verify(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
        }
        verifyNoMoreInteractions(tokenPermissions);
    }

    private static Stream<Arguments> provideExpectedPermissions(final String httpMethod) {
        final String[] mappedPermissions =
                EXPECTED_MAPPING.apply(httpMethod).toArray(new String[0]);

        return Stream.of(arguments(httpMethod, mappedPermissions, true),
                arguments(httpMethod, mappedPermissions, false));
    }

    private static Stream<Arguments> providePermissions() {
        final List<String> methods =
                Arrays.asList("POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "CONNECT", "OPTIONS",
                        "TRACE");

        return methods.stream()
                .flatMap(MappablePermissionsInterceptorTest::provideExpectedPermissions);
    }

    @Test
    @DisplayName("preHandle does nothing when the HTTP method is ignored")
    void preHandleIgnoreRequest() {
        when(request.getMethod()).thenReturn("OTHER");

        assertThat(testInterceptor.preHandle(request, response, HANDLER), is(true));

        verifyNoMoreInteractions(request);
    }

    @Test
    @DisplayName("postHandle removes the TokenPermissions object from the request")
    void postHandle() {
        testInterceptor.postHandle(request, response, HANDLER, null);

        verify(request).setAttribute("token_permissions", null);
    }

    @Test
    @DisplayName("postHandle does nothing when the HTTP method is ignored")
    void postHandleIgnoredMethod() {
        when(request.getMethod()).thenReturn("IGNORED");

        testInterceptor.postHandle(request, response, HANDLER, null);

        verify(testInterceptor, never()).getTokenPermissionsFromRequest(request);
        verifyNoMoreInteractions(request);
    }

    @Test
    @DisplayName("preHandle ignores API key request if ignoreAPIKeyRequests flag set")
    void ignoreAPIKeyRequestsGetRequest() {
        final MappablePermissionsInterceptor ignoringApiInterceptor =
                new MappablePermissionsInterceptor(USER_PROFILE_KEY, true, EXPECTED_MAPPING);

        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn(
                SecurityConstants.API_KEY_IDENTITY_TYPE);

        assertThat(ignoringApiInterceptor.preHandle(request, response, HANDLER), is(true));

        verifyNoMoreInteractions(request);
    }

    @Test
    @DisplayName("preHandle rejects if ignoreAPIKeyRequests flag set for non-API key requests")
    void notIgnoreNonAPIKeyRequestsGetRequest() {
        final MappedCRUDAuthenticationInterceptor ignoringApiInterceptor =
                new MappedCRUDAuthenticationInterceptor(USER_PROFILE_KEY, true);
        final MappedCRUDAuthenticationInterceptor spyInterceptor =
                Mockito.spy(ignoringApiInterceptor);

        doReturn(Optional.of(tokenPermissions)).when(spyInterceptor)
                .getTokenPermissionsFromRequest(request);
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(EricConstants.ERIC_IDENTITY_TYPE)).thenReturn("oauth");

        assertThat(spyInterceptor.preHandle(request, response, HANDLER), is(false));

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void setupTokenPermissions() {
        doReturn(Optional.of(tokenPermissions)).when(testInterceptor)
                .getTokenPermissionsFromRequest(request);
    }
}