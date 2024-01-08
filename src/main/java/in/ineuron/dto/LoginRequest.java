package in.ineuron.dto;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class LoginRequest {

	@NotNull(message = "Email is required, please enter email")
	@NotEmpty(message = "Email should not be empty")
	@Email(regexp = "^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$",
	message="invalid email!")
	private String email;


	@NotBlank(message = "Password should not be empty or null")
    @Pattern(regexp = "^(?!.*\\s).*$",
             message = "Invalid password")
	private String password;


	public void setEmail(String email) {
		this.email = email.trim();
	}
	
	public void setPassword(String password) {
		this.password = password.trim();
	}
	
	
}
