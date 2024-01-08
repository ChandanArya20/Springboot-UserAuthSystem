package in.ineuron.dto;

import lombok.Data;

@Data
public class UpdateUserPasswordDTO {

    private String email;
    private String newPassword;
}
