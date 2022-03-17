package com.ulfg.bcrypt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BcryptConfig {
    @Value("${strength}")
    private String strength;
    @Value("${version}")
    private String version;

    public String getVersion() {
        switch (version) {
            case "2Y" : return "$2y";
            case "2B" : return "$2b";
            default: return "$2a";
        }
    }

    public int getStrength() {
        try {
            return Integer.parseInt(strength);
        }catch(NumberFormatException e){
            return -1;
        }
    }
}
