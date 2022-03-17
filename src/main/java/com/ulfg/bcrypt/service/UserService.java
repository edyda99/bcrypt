package com.ulfg.bcrypt.service;

import com.ulfg.bcrypt.entities.User;
import com.ulfg.bcrypt.repo.UserRepository;
import com.ulfg.bcrypt.service.impl.Encoder;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final Encoder encoder;

    @SneakyThrows
    public void saveUser(String userId, String name, String password) {
        User initialUser = new User(userId, name, password, LocalDate.now().toEpochDay());
        userRepository.save(initialUser);
        User user = new User("2", "ed", encoder.encode(password,userId), LocalDate.now().toEpochDay());
        userRepository.save(user);
    }
}
