package uk.gov.companieshouse.api.interceptor;

import java.io.IOException;
import java.util.HashMap;

import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import uk.gov.companieshouse.api.util.security.AuthorisationUtil;
import uk.gov.companieshouse.logging.Logger;
import uk.gov.companieshouse.logging.LoggerFactory;

/**
 * Checks the request to see if the request contains the required role permission
 * stored in the header field `ERIC-Authorised-Roles`. Interceptor is only used 
 * for use when verifying an admin user
 */
public class RolePermissionInterceptor implements HandlerInterceptor {

   private final Logger logger;

   private final String requiredRolePermission;

   private final static HashMap<String,Object> EMPTY_MAP =  new HashMap<String,Object>();
    
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
      boolean isOauthUser = AuthorisationUtil.isOauth2User(request);
      if (isOauthUser){
         boolean hasRole = AuthorisationUtil.getAuthorisedRoles(request).contains(requiredRolePermission);
         if (hasRole) {
            logger.debugRequest(request, String.format("authorised user has the correct role: %s ", requiredRolePermission), EMPTY_MAP );
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