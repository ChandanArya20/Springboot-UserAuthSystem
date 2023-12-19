package in.ineuron.services;

public interface TokenStorageService {

    String generateToken();

    boolean isValidToken(String token);

    void removeToken(String token);
}
