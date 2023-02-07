package uk.gov.companieshouse.api.interceptor;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.doReturn;
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
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import uk.gov.companieshouse.api.util.security.Permission;
import uk.gov.companieshouse.api.util.security.TokenPermissions;

@ExtendWith(MockitoExtension.class)
class MappedCRUDAuthenticationInterceptorTest {
    private static final Object HANDLER = new Object();
    private static final Permission.Key USER_PROFILE_KEY = Permission.Key.USER_PROFILE;
    private static final PermissionsMapping EXPECTED_MAPPING = PermissionsMapping.builder()
            .defaultAllOf(Permission.Value.READ)
            .mapAllOf(HttpMethod.PUT.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.PATCH.toString(), Permission.Value.UPDATE)
            .mapAllOf(HttpMethod.POST.toString(), Permission.Value.CREATE)
            .build();

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private TokenPermissions tokenPermissions;

    @Spy
    private MappedCRUDAuthenticationInterceptor testInterceptor =
            new MappedCRUDAuthenticationInterceptor(USER_PROFILE_KEY, "IGNORED");

    @Test
    @DisplayName("constructor with ignore API key")
    void constructorWithIgnoreApiKey() {
        final MappedCRUDAuthenticationInterceptor interceptor =
                new MappedCRUDAuthenticationInterceptor(USER_PROFILE_KEY, true);

        assertThat(interceptor.getTokenPermissionsFromRequest(request), is(Optional.empty()));

    }

    @ParameterizedTest(name = "{index}: preHandle with a {0} request with validity {2}")
    @MethodSource({"providePermissions"})
    void preHandleAuthorisedValidity(final String httpMethod, final String[] requiredPermissions,
            final boolean isValid) {
        doReturn(Optional.of(tokenPermissions)).when(testInterceptor)
                .getTokenPermissionsFromRequest(request);
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
                .flatMap(MappedCRUDAuthenticationInterceptorTest::provideExpectedPermissions);
    }

}