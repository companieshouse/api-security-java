package uk.gov.companieshouse.api.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomCorsFilter implements Filter {

    private List<String> externalMethods;
    private static final String OPTIONS_METHOD = "OPTIONS";
    private static final String ERIC_ALLOWED_ORIGIN = "ERIC-Allowed-Origin";

    public CustomCorsFilter(List<String> externalMethods) {
        this.externalMethods = externalMethods;
    }

    // Required for Java 8 Filter
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    // Required for Java 8 Filter
    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        String method = httpServletRequest.getMethod();

        if (CorsUtils.isCorsRequest(httpServletRequest)) {
            if (method.equalsIgnoreCase(OPTIONS_METHOD)) {
                httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
                httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, "*");
                httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "*");
                httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "3600");
                httpServletResponse.setStatus(HttpServletResponse.SC_NO_CONTENT);
                return;
            } else {
                httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, String.join(",",externalMethods));
                String allowedOrigin = httpServletRequest.getHeader(ERIC_ALLOWED_ORIGIN);
                if (!externalMethods.contains(method) || (allowedOrigin == null || allowedOrigin.isEmpty())) {
                    httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "cors forbidden error");
                    return;
                }
            }
        }
        chain.doFilter(request, response);
    }
}
