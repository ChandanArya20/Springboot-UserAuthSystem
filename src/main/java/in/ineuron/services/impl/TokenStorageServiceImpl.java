package in.ineuron.services.impl;

import in.ineuron.services.TokenStorageService;
import org.springframework.stereotype.Service;

import javax.annotation.PreDestroy;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class TokenStorageServiceImpl implements TokenStorageService {
    private static final long CLEANUP_INTERVAL_MINUTES = 10;
    private static final long TOKEN_EXPIRY_DURATION_MILLIS = 7 * 24 * 60 * 60 * 1000; // 7 days milliseconds
//    private static final long TOKEN_EXPIRY_DURATION_MILLIS = 60 * 1000; // 1 min mins milliseconds

    private final Map<String, Long> tokenMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);

    public TokenStorageServiceImpl() {
        // Schedule a cleanup task to remove expired tokens every 1 minute.
        executorService.scheduleAtFixedRate(this::cleanUpExpiredTokens, CLEANUP_INTERVAL_MINUTES, CLEANUP_INTERVAL_MINUTES, TimeUnit.SECONDS);
    }

    @Override
    public String generateToken() {
        String token = UUID.randomUUID().toString();
        long creationTime = System.currentTimeMillis();
        tokenMap.put(token, creationTime);
        // Log statement: System.out.println("Auth token generated: " + token);
        return token;
    }

    @Override
    public boolean isValidToken(String token) {
        Long creationTime = tokenMap.get(token);
        return creationTime != null && (System.currentTimeMillis() - creationTime <= TOKEN_EXPIRY_DURATION_MILLIS);
    }

    @Override
    public void removeToken(String token){
        tokenMap.remove(token);
    }

    private void cleanUpExpiredTokens() {
        long currentTime = System.currentTimeMillis();
        // Iterate through the token map and remove entries older than the expiration duration.
        tokenMap.entrySet().removeIf(entry -> (currentTime - entry.getValue() > TOKEN_EXPIRY_DURATION_MILLIS));
        // Log statement: System.out.println("Expired tokens cleaned up");

//        System.out.println("TokenStorageServiceImpl.cleanUpExpiredTokens");
    }

    // Shutdown the executor service when the application stops
    @PreDestroy
    public void shutdownExecutorService() {
        executorService.shutdown();
    }
}
