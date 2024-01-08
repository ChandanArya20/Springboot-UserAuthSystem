package in.ineuron.utils;

import in.ineuron.services.TokenStorageService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import java.util.HashMap;
import java.util.Map;

@Component
public class UserUtils {

    @Autowired
    private TokenStorageService tokenService;

    /**
     * Validate user credentials and extract error messages and field names.
     *
     * @param result BindingResult object containing validation errors
     * @return Map containing field names as keys and error messages as values
     */
    public Map<String, String> validateUserCredential(BindingResult result){

        Map<String, String> errorsMap = new HashMap<>();

        if (result.hasErrors()) {
            // Extract error messages and field names
            for (ObjectError error : result.getAllErrors()) {
                if (error instanceof FieldError) {
                    FieldError fieldError = (FieldError) error;
                    errorsMap.put(fieldError.getField(), error.getDefaultMessage());
                } else {
                    errorsMap.put("global", error.getDefaultMessage());
                }
            }
        }
        // Return only error messages and field names
        return errorsMap;
    }

    /**
     * Get authentication token from the request's cookies.
     *
     * @param request HttpServletRequest object
     * @return Authentication token or null if not found
     */
    public String getAuthToken(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();
        String authToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("auth-token".equals(cookie.getName()) && !cookie.getValue().isBlank()) {
                    authToken = cookie.getValue();
                    break;
                }
            }
        }
        return authToken;
    }

    public String getOTPAuthToken(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();
        String authToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("otpVerified-token".equals(cookie.getName()) && !cookie.getValue().isBlank()) {
                    authToken = cookie.getValue();
                    break;
                }
            }
        }
        return authToken;
    }

    /**
     * Validate the authenticity of the provided authentication token.
     *
     * @param request HttpServletRequest object
     * @return True if the token is valid, otherwise false
     */
    public boolean validateToken(HttpServletRequest request) {

        String authToken = getAuthToken(request);

        System.out.println(authToken);

        if(authToken != null){
            return tokenService.isValidToken(authToken);
        } else {
            return false;
        }
    }

    public boolean validateOTPAuthToken(HttpServletRequest request) {

        String authToken = getOTPAuthToken(request);

        System.out.println(authToken);

        if(authToken != null){
            return tokenService.isValidToken(authToken);
        } else {
            return false;
        }
    }
}
