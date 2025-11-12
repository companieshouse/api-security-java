package uk.gov.companieshouse.api.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Intercepts incoming HTTP requests to validate application authentication tokens.
 * Uses {@link CisAppTokenValidator} to ensure that requests contain a valid token
 * with expected claims (tenant ID and client IDs). If validation fails, sets the response
 * status to 401 Unauthorized and prevents further request processing.
 * <p>
 * Intended for use in Spring Boot applications as a {@link HandlerInterceptor}.
 */
@Component
public class CisAppAuthenticationInterceptor implements HandlerInterceptor {

    private final Logger logger;

    private final String tenantId;
    private final String logicAppClientId;
    private final String cisAppClientId;

    private final CisAppTokenValidator cisAppTokenValidator;

    @Bean
    public CisAppTokenValidator applicationTokenValidator() {
        return new CisAppTokenValidator(tenantId, logicAppClientId, cisAppClientId);
    }
    
    public CisAppAuthenticationInterceptor(String tenantId, String logicAppClientId, String cisAppClientId) {
        this.tenantId = tenantId;
        this.logicAppClientId = logicAppClientId;
        this.cisAppClientId = cisAppClientId;
        this.cisAppTokenValidator = applicationTokenValidator();
        logger = LoggerFactory.getLogger(String.valueOf(CisAppAuthenticationInterceptor.class));
    }

    @Override
    public boolean preHandle(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Object handler) {
        if (!cisAppTokenValidator.hasValidApplicationToken(request)) {
            logger.debugRequest(request, "No valid application token supplied", null);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }
        return true;
    }
}