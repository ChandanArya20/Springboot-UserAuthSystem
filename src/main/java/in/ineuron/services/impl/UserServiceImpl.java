package in.ineuron.services.impl;

import in.ineuron.dto.UserResponse;
import in.ineuron.models.User;
import in.ineuron.repositories.UserRepository;
import in.ineuron.services.UserService;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private UserRepository userRepo;

    public UserServiceImpl(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public Boolean isUserAvailableByPhone(String phone) {

        return userRepo.existsByPhone(phone);
    }

    @Override
    public Boolean isUserAvailableByEmail(String email) {

        return userRepo.existsByEmail(email);
    }

    @Override
    public User fetchUserByPhone(String phone) {

        return userRepo.findByPhone(phone);
    }

    @Override
    public User fetchUserByEmail(String email) {

        return userRepo.findByEmail(email);
    }

    @Override
    public void registerUser(User user) {

        User regUser = userRepo.save(user);
        System.out.println(regUser);
    }

    @Override
    public boolean updateUserPassword(Long userId, String newPassword) {

        Optional<User> userOptional = userRepo.findById(userId);

        if(userOptional.isPresent()){
            User user = userOptional.get();
            user.setPassword(newPassword);
            userRepo.save(user);
            return true;
        }
        return false;
    }

    @Override
    public UserResponse fetchUserDetails(Long userId) {

        Optional<User> userOptional = userRepo.findById(userId);
        if(userOptional.isPresent()) {

            User user = userOptional.get();
            UserResponse userResponse = new UserResponse();
            BeanUtils.copyProperties(user, userResponse);

            return userResponse;
        }

        return null;
    }

}
