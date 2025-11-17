package uk.gov.companieshouse.api.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CisAppAuthenticationInterceptorTest {

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private CisAppTokenValidator cisAppTokenValidatorMock;
    
    private CisAppAuthenticationInterceptor cisAppAuthenticationInterceptor;

    @BeforeEach
    void setUp() {
        cisAppAuthenticationInterceptor = spy(new CisAppAuthenticationInterceptor("tenant", "logicApp", "cisApp"));
        try {
            var field = CisAppAuthenticationInterceptor.class.getDeclaredField("cisAppTokenValidator");
            field.setAccessible(true);
            field.set(cisAppAuthenticationInterceptor, cisAppTokenValidatorMock);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void preHandle_validToken_returnsTrue() {
        when(cisAppTokenValidatorMock.hasValidApplicationToken(httpServletRequestMock)).thenReturn(true);

        boolean result = cisAppAuthenticationInterceptor.preHandle(httpServletRequestMock, httpServletResponseMock, new Object());

        assertTrue(result);
        verify(httpServletResponseMock, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void preHandle_invalidToken_setsUnauthorizedAndReturnsFalse() {
        when(cisAppTokenValidatorMock.hasValidApplicationToken(httpServletRequestMock)).thenReturn(false);

        boolean result = cisAppAuthenticationInterceptor.preHandle(httpServletRequestMock, httpServletResponseMock, new Object());

        assertFalse(result);
        verify(httpServletResponseMock, times(1)).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
