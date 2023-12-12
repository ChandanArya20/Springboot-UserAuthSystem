package in.ineuron.restcontrollers;

import in.ineuron.dto.*;
import in.ineuron.models.User;
import in.ineuron.services.OTPSenderService;
import in.ineuron.services.OTPStorageService;
import in.ineuron.services.UserService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

	public UserController(UserService userService) {
		this.userService = userService;
	}

	// Endpoint for registering a new user
	@PostMapping("/register")
	public ResponseEntity<?> registerUser(@RequestBody RegisterRequest requestData) {
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
	public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginData, HttpServletResponse response) {
		if (loginData.getPhone() != null) {
			// Login using phone number
			User user = userService.fetchUserByPhone(loginData.getPhone());
			if (user == null) {
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Account not found for this phone No.");
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
		} else {
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
	}

	// Endpoint to retrieve user data by ID
	@GetMapping("/{user-id}")
	public ResponseEntity<?> getWholeUserData(@PathVariable(name = "user-id") String userId) {
		// Fetch user details by ID
		UserResponse userResponse = userService.fetchUserDetails(userId);
		if (userResponse != null)
			return ResponseEntity.ok(userResponse);
		else
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User id not found");
	}
}
