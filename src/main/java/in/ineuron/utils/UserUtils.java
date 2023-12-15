package in.ineuron.utils;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import java.util.HashMap;
import java.util.Map;

@Component
public class UserUtils {

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

}
