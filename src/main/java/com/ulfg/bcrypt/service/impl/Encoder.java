package com.ulfg.bcrypt.service.impl;

import com.ulfg.bcrypt.config.BcryptConfig;
import com.ulfg.bcrypt.service.CustomBCrypt;
import com.ulfg.bcrypt.service.PasswordEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;

import static com.ulfg.bcrypt.util.CustomBCryptUtil.MAX_LOG_ROUNDS;
import static com.ulfg.bcrypt.util.CustomBCryptUtil.MIN_LOG_ROUNDS;

@Service
public class Encoder implements PasswordEncoder {

    private final CustomBCrypt customBCrypt;

    private final Log logger = LogFactory.getLog(getClass());

    private final SecureRandom random;

    private final BcryptConfig bcryptConfig;


    public Encoder(BcryptConfig bcryptConfig, CustomBCrypt customBCrypt) {
        random = new SecureRandom();
        if (bcryptConfig.getStrength() != -1 && (bcryptConfig.getStrength() < MIN_LOG_ROUNDS || bcryptConfig.getStrength() > MAX_LOG_ROUNDS)) {
            throw new IllegalArgumentException("Bad strength");
        }
        this.bcryptConfig = bcryptConfig;
        this.customBCrypt = customBCrypt;
    }

    @Override
    public String encode(CharSequence rawPassword,String userId) throws Exception {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        String salt = getSalt();
        return customBCrypt.hashpw(rawPassword.toString(), salt, userId);
    }

    private String getSalt() {
        if (this.random != null) {
            return customBCrypt.gensalt(this.bcryptConfig.getVersion(), this.bcryptConfig.getStrength(), this.random);
        }
        return customBCrypt.gensalt(this.bcryptConfig.getVersion(), this.bcryptConfig.getStrength());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword, String userId) throws Exception {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        if (encodedPassword == null || encodedPassword.length() == 0) {
            this.logger.warn("Empty encoded password");
            return false;
        }
        return customBCrypt.checkpw(rawPassword.toString(), encodedPassword, userId,bcryptConfig.getVersion());
    }
}