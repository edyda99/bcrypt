package com.ulfg.bcrypt;

import com.ulfg.bcrypt.entities.User;
import com.ulfg.bcrypt.repo.UserRepository;
import com.ulfg.bcrypt.service.UserService;
import com.ulfg.bcrypt.service.impl.Encoder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class BcryptApplicationTests {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private Encoder encoder;
    @Autowired
    private UserService userService;
    @Test
    void contextLoads() throws Exception {
        userService.saveUser("2", "ed", "password");
        Optional<User> user = userRepository.findById("2");
        if (user.isEmpty()) throw new Exception();
        System.out.println("this is the encoded password: " + user.get().getPassword());
        boolean password1 = encoder.matches("password", user.get().getPassword(), "2");
        assertTrue(password1);
    }
}
