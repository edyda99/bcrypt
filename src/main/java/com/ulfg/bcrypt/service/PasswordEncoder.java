package com.ulfg.bcrypt.service;

public interface PasswordEncoder {

    /**
     * Encode the raw password known as plaintext applies a SHA-3 hashing
     * concatinated with salt
     * @param rawPassword   know as plaintext
     * @param userId        the user-id save in the database
     */
    String encode(CharSequence rawPassword,String userId) throws Exception;

    /**
     * Verify the encoded password obtained from storage matches the submitted raw
     * password after it too is encoded. Returns true if the passwords match, false if
     * they do not. The stored password itself is never decoded, because hashing is one way encryption.
     *
     * @param rawPassword     the raw password to encode and match
     * @param encodedPassword the encoded password from storage to compare with
     * @return true if the raw password, after encoding, matches the encoded password from
     * storage
     */
    boolean matches(CharSequence rawPassword, String encodedPassword, String userId) throws Exception;
}
