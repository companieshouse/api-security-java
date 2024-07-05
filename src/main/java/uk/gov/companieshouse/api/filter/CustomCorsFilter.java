package uk.gov.companieshouse.api.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.web.cors.CorsUtils;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomCorsFilter implements Filter {

    private List<String> externalMethods;
    private String OPTIONS_METHOD = "OPTIONS";
    private String ERIC_ALLOWED_ORIGIN = "ERIC-Allowed-Origin";
    
    public CustomCorsFilter(List<String> externalMethods) {
        this.externalMethods = externalMethods;
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
