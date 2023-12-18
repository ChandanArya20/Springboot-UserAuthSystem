package in.ineuron.models;

import lombok.Data;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Data
@Entity
public class User {

	@Id
	@GenericGenerator(name = "gen",strategy = "in.ineuron.idgenerator.IdGenerator")
	@GeneratedValue(generator = "gen")
	private String id;
	
	@Column(nullable = false)
	private String name;

	@Column(unique = true, nullable = false)
	private String email;

	@Column(unique = true)
	private String phone;

	@Column(nullable = false)
	private String password;

}





