package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;

import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Checks the request to see if the request contains the required role permission
 * stored in the header field `ERIC-Authorised-Roles`. 
 * 
 * Interceptor is only for use when verifying an admin user
 */
public class RolePermissionInterceptor implements HandlerInterceptor {

   private final Logger logger;

   private final String requiredRolePermission;
    
   public RolePermissionInterceptor(final String requiredRolePermission) {         
      this.logger = LoggerFactory.getLogger(String.valueOf(RolePermissionInterceptor.class));
      this.requiredRolePermission = requiredRolePermission;
   }

   public RolePermissionInterceptor(String loggingNamespace, final String requiredRolePermission) {
      this.logger = LoggerFactory.getLogger(loggingNamespace);
      this.requiredRolePermission = requiredRolePermission;
  }

   @Override
   public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
      if (AuthorisationUtil.isOauth2User(request)){
         if (AuthorisationUtil.getAuthorisedRoles(request).contains(requiredRolePermission)) {
            logger.debug(String.format("authorised user has the correct role: %s ", requiredRolePermission));
            return true;         
         } else {
            logger.debug("user does not have the correct role permission");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
         }
      } else{
         logger.debug("Identity type provided was not oauth2");
         response.setStatus(HttpServletResponse.SC_FORBIDDEN);
         return false;
      }
   }
}   