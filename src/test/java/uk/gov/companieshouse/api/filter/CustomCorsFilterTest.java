package uk.gov.companieshouse.api.filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class CustomCorsFilterTest {

    private static final String OPTIONS_METHOD = "OPTIONS";
    private static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
    private static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
    private static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
    private static final String ERIC_ALLOWED_ORIGIN = "ERIC-Allowed-Origin";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @InjectMocks
    private CustomCorsFilter customCorsFilter;

    private List<String> externalMethods;

    @BeforeEach
    public void setUp() {
        externalMethods = List.of("GET", "POST");
        customCorsFilter = new CustomCorsFilter(externalMethods);
    }

    @Test
    public void testDoFilterOptionsMethod() throws IOException, ServletException {
        setupCorsRequest("OPTIONS");
        when(request.getMethod()).thenReturn(OPTIONS_METHOD);

        customCorsFilter.doFilter(request, response, chain);

        verify(response).setHeader(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        verify(response).setHeader(ACCESS_CONTROL_ALLOW_HEADERS, "*");
        verify(response).setHeader(ACCESS_CONTROL_MAX_AGE, "3600");
        verify(response).setStatus(HttpServletResponse.SC_NO_CONTENT);
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilterAllowedMethod() throws IOException, ServletException {
        setupCorsRequest("GET");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(ERIC_ALLOWED_ORIGIN)).thenReturn("example.com");

        customCorsFilter.doFilter(request, response, chain);

        verify(response).setHeader(ACCESS_CONTROL_ALLOW_METHODS, String.join(",", externalMethods));
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testDoFilterNotAllowedMethod() throws IOException, ServletException {
        setupCorsRequest("DELETE");
        when(request.getMethod()).thenReturn("DELETE");

        customCorsFilter.doFilter(request, response, chain);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "cors forbidden error");
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilterMissingOriginHeader() throws IOException, ServletException {
        setupCorsRequest("GET");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(ERIC_ALLOWED_ORIGIN)).thenReturn(null);

        customCorsFilter.doFilter(request, response, chain);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "cors forbidden error");
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilterEmptyOriginHeader() throws IOException, ServletException {
        setupCorsRequest("GET");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader(ERIC_ALLOWED_ORIGIN)).thenReturn("");

        customCorsFilter.doFilter(request, response, chain);

        verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "cors forbidden error");
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    public void testDoFilterNonCorsRequest() throws IOException, ServletException {
        when(request.getMethod()).thenReturn("GET");

        customCorsFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    private void setupCorsRequest(String method) {
        when(request.getHeader("Origin")).thenReturn("http://example.com");
        when(request.getHeader("Access-Control-Request-Method")).thenReturn("GET");
    }
}