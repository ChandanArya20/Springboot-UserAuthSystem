package in.ineuron.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class RegisterRequest {

	@NotBlank(message = "Name should not be empty or null")
	@Size(min=3, message = "Name should be greater than 2")
	private String name;

//	@NotBlank(message = "Phone No. should not be empty or null")
//	@Pattern(regexp = "^[6-9][0-9]*$",
//						message="invalid phone!")
	private String phone;

	@NotBlank(message = "Email should not be empty or null")
	@Email(regexp = "^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$",
	message="invalid email!")
	private String email;
	
	@NotBlank(message = "Password should not be empty or null")
    @Pattern(regexp = "^(?!.*\\s).*$",
             message = "Space is not allowed")
	private String password;


	public void setName(String name) {
		this.name = name.trim();
	}

	
	public void setPhone(String phone) {
		this.phone = phone.trim();
	}
	
	public void setEmail(String email) {
		this.email = email.trim();
	}


	public void setPassword(String password) {
		this.password = password.trim();
	}
	
}
