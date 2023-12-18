package in.ineuron.dto;

import lombok.Getter;

@Getter
public class OTPEntry {
    private final String otp;
    private final long creationTime;

    public OTPEntry(String otp, long creationTime) {
        this.otp = otp;
        this.creationTime = creationTime;
    }

}

