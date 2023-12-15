package in.ineuron.restcontrollers;

import in.ineuron.dto.*;
import in.ineuron.models.User;
import in.ineuron.services.OTPSenderService;
import in.ineuron.services.OTPStorageService;
import in.ineuron.services.UserService;
import in.ineuron.utils.UserUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/user")
public class UserController {

	private final UserService userService;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	private OTPSenderService otpSender;

	@Autowired
	private OTPStorageService otpStorage;

	@Autowired
	private UserUtils userUtils;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	// Endpoint for registering a new user
	@PostMapping("/register")
	public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest requestData, BindingResult result) {

		//checks the bean field errors
		Map<String, String> errorResults = userUtils.validateUserCredential(result);
		if(!errorResults.isEmpty()){
			return ResponseEntity.badRequest().body(errorResults);
		}

		// Check if the email is already registered
		if (userService.isUserAvailableByEmail(requestData.getEmail())) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already registered with another account");
		}
		// Check if the phone number is already registered
		if (requestData.getPhone() != null && userService.isUserAvailableByPhone(requestData.getPhone())) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Phone No. already registered with another account");
		} else {
			// Copy request data to User entity
			User user = new User();
			BeanUtils.copyProperties(requestData, user);

			// Encrypt the user's password
			String encodedPwd = passwordEncoder.encode(user.getPassword());
			user.setPassword(encodedPwd);

			// Register the user in the system
			userService.registerUser(user);

			return ResponseEntity.ok("User registered successfully...");
		}
	}

	// Endpoint for user login
	@PostMapping("/login")
	public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginData, BindingResult result, HttpServletResponse response) {

		//checks the bean field errors
		Map<String, String> errorResults = userUtils.validateUserCredential(result);
		if(!errorResults.isEmpty()){
			return ResponseEntity.badRequest().body(errorResults);
		}

		// Login using email
		User user = userService.fetchUserByEmail(loginData.getEmail());
		if (user == null) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Account not found for this email");
		} else if (!passwordEncoder.matches(loginData.getPassword(), user.getPassword())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
		} else {
			// Create a response object and set an authentication token cookie
			UserResponse userResponse = new UserResponse();
			BeanUtils.copyProperties(user, userResponse);

			String token = UUID.randomUUID().toString();

			Cookie cookie = new Cookie("auth-token", token);
			cookie.setHttpOnly(true);
			cookie.setSecure(true);
			response.addCookie(cookie);

			return ResponseEntity.ok(userResponse);
		}
	}

	@GetMapping("/send-otp")
	public ResponseEntity<String> sendOTPByPhone(@RequestParam("email") String email ) throws MessagingException {

		if(userService.isUserAvailableByEmail(email)){
			Integer OTP=-1;
			OTP = otpSender.sendOTPByEmail(email);

			otpStorage.storeOTP(email, String.valueOf(OTP));

			return ResponseEntity.ok("Sent OTP: "+OTP);
		}else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Account not found for "+email);
		}
	}

	@GetMapping("/verify-otp")
	public ResponseEntity<String> verifyOTPByPhone(
			@RequestParam("email") String email,
			@RequestParam String otp ) throws MessagingException {

			if(userService.isUserAvailableByEmail(email)){

				if(otpStorage.verifyOTP(email, otp)){
					otpStorage.removeOTP(email);
					return ResponseEntity.ok("verified successfully.. ");
				} else {
					return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("OTP verification failed.. ");
				}

			} else{
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Account not found for "+email);
			}
	}

	@PostMapping("/otp-verified/update-password")
	public ResponseEntity<?> UpdateUserPasswordAfterOTPVerified(
			@RequestBody UpdateUserPasswordDTO userCredential ) {

		User user= userService.fetchUserByEmail(userCredential.getEmail());

		if(user!=null){
			userService.updateUserPassword(user.getId(), passwordEncoder.encode(userCredential.getNewPassword()));

			return ResponseEntity.ok("Password updated successfully..");

		} else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User name not found...");
		}
	}

}
