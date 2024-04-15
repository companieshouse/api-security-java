package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.HashMap;

import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

public class RoleInterceptor implements HandlerInterceptor {

   private final Logger logger;

   private final String allowedRole;

   private final static HashMap<String,Object> EMPTY_MAP =  new HashMap<String,Object>();
    
   public RoleInterceptor(final String allowedRole) {         

      this.logger = LoggerFactory.getLogger(String.valueOf(RoleInterceptor.class));
      this.allowedRole = allowedRole;
   }

   public RoleInterceptor(String loggingNamespace, final String allowedRole) {
      this.logger = LoggerFactory.getLogger(loggingNamespace);
      this.allowedRole = allowedRole;
  }

   @Override
   public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
      boolean isOauthUser = AuthorisationUtil.isOauth2User(request);
      if (isOauthUser){
         boolean hasRole = AuthorisationUtil.getAuthorisedRoles(request).contains(allowedRole);
         if (hasRole) {
            logger.debugRequest(request, String.format("authorised user has the correct role: %s ", allowedRole), EMPTY_MAP );
            return true;         
         } else {
            logger.debugRequest(request, "user does not have the correct role", EMPTY_MAP);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
         }
      } else{
         logger.debugRequest(request, "user does not have the correct role", EMPTY_MAP);
         response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
         return false;
      }
   }
}   