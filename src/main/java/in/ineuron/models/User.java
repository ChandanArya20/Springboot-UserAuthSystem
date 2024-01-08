package in.ineuron.models;

import jakarta.persistence.*;
import lombok.Data;


@Data
@Entity
public class User {

	@Id
//	@GenericGenerator(name = "gen",strategy = "in.ineuron.idgenerator.IdGenerator")
//	@GeneratedValue(generator = "gen")
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	
	@Column(nullable = false)
	private String name;

	@Column(unique = true, nullable = false)
	private String email;

	@Column(unique = true)
	private String phone;

	@Column(nullable = false)
	private String password;

}





