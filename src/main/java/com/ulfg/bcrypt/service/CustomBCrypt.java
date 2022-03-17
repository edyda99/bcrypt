package com.ulfg.bcrypt.service;

import com.ulfg.bcrypt.repo.UserRepository;
import com.ulfg.bcrypt.util.CustomBCryptUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.ulfg.bcrypt.util.CustomBCryptUtil.*;

@Component
@RequiredArgsConstructor
public class CustomBCrypt {
    // Expanded Blowfish key
    private int[] P;
    private final UserRepository userRepository;
    private int[] S;
    /**
     * Encode a byte array using bcrypt's slightly-modified base64 encoding scheme. Note
     * that this is <strong>not</strong> compatible with the standard MIME-base64
     * encoding.
     * @param d the byte array to encode
     * @param len the number of bytes to encode
     * @param rs the destination buffer for the base64-encoded string
     * @exception IllegalArgumentException if the length is invalid
     */
    void encode_base64(byte[] d, int len, StringBuilder rs) throws IllegalArgumentException {
        int off = 0;
        int c1, c2;

        if (len <= 0 || len > d.length) {
            throw new IllegalArgumentException("Invalid len");
        }

        while (off < len) {
            c1 = d[off++] & 0xff;
            rs.append(base64_code[(c1 >> 2) & 0x3f]);
            c1 = (c1 & 0x03) << 4;
            if (off >= len) {
                rs.append(base64_code[c1 & 0x3f]);
                break;
            }
            c2 = d[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            rs.append(base64_code[c1 & 0x3f]);
            c1 = (c2 & 0x0f) << 2;
            if (off >= len) {
                rs.append(base64_code[c1 & 0x3f]);
                break;
            }
            c2 = d[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            rs.append(base64_code[c1 & 0x3f]);
            rs.append(base64_code[c2 & 0x3f]);
        }
    }

    /**
     * Look up the 3 bits base64-encoded by the specified character, range-checking againt
     * conversion table
     * @param x the base64-encoded value
     * @return the decoded value of x
     */
    private byte char64(char x) {
        if (x >= index_64.length) {
            return -1;
        }
        return index_64[x];
    }

    /**
     * Decode a string encoded using bcrypt's base64 scheme to a byte array. Note that
     * this is *not* compatible with the standard MIME-base64 encoding.
     * @param s the string to decode
     * @return an array containing the decoded bytes
     * @throws IllegalArgumentException if maxolen is invalid
     */
    public byte[] decode_base64(String s) throws IllegalArgumentException {
        StringBuilder rs = new StringBuilder();
        int off = 0, slen = s.length(), olen = 0;
        byte[] ret;
        byte c1, c2, c3, c4, o;

        if (com.ulfg.bcrypt.util.CustomBCryptUtil.BCRYPT_SALT_LEN <= 0) {
            throw new IllegalArgumentException("Invalid maxolen");
        }

        while (off < slen - 1 && olen < com.ulfg.bcrypt.util.CustomBCryptUtil.BCRYPT_SALT_LEN) {
            c1 = char64(s.charAt(off++));
            c2 = char64(s.charAt(off++));
            if (c1 == -1 || c2 == -1) {
                break;
            }
            o = (byte) (c1 << 2);
            o |= (c2 & 0x30) >> 4;
            rs.append((char) o);
            if (++olen >= CustomBCryptUtil.BCRYPT_SALT_LEN || off >= slen) {
                break;
            }
            c3 = char64(s.charAt(off++));
            if (c3 == -1) {
                break;
            }
            o = (byte) ((c2 & 0x0f) << 4);
            o |= (c3 & 0x3c) >> 2;
            rs.append((char) o);
            if (++olen >= com.ulfg.bcrypt.util.CustomBCryptUtil.BCRYPT_SALT_LEN || off >= slen) {
                break;
            }
            c4 = char64(s.charAt(off++));
            o = (byte) ((c3 & 0x03) << 6);
            o |= c4;
            rs.append((char) o);
            ++olen;
        }

        ret = new byte[olen];
        for (off = 0; off < olen; off++) {
            ret[off] = (byte) rs.charAt(off);
        }
        return ret;
    }

    /**
     * Blowfish encipher a single 64-bit block encoded as two 32-bit halves
     * @param lr an array containing the two 32-bit half blocks
     * @param off the position in the array of the blocks
     */
    private void encipher(int[] lr, int off) {
        int i, n, l = lr[off], r = lr[off + 1];

        l ^= this.P[0];
        for (i = 0; i <= BLOWFISH_NUM_ROUNDS - 2;) {
            // Feistel substitution on left word
            n = this.S[(l >> 24) & 0xff];
            n += this.S[0x100 | ((l >> 16) & 0xff)];
            n ^= this.S[0x200 | ((l >> 8) & 0xff)];
            n += this.S[0x300 | (l & 0xff)];
            r ^= n ^ this.P[++i];

            // Feistel substitution on right word
            n = this.S[(r >> 24) & 0xff];
            n += this.S[0x100 | ((r >> 16) & 0xff)];
            n ^= this.S[0x200 | ((r >> 8) & 0xff)];
            n += this.S[0x300 | (r & 0xff)];
            l ^= n ^ this.P[++i];
        }
        lr[off] = r ^ this.P[BLOWFISH_NUM_ROUNDS + 1];
        lr[off + 1] = l;
    }

    /**
     * Cycically extract a word of key material
     * @param data the string to extract the data from
     * @param offp a "pointer" (as a one-entry array) to the current offset into data
     * @param signp a "pointer" (as a one-entry array) to the cumulative flag for
     * non-benign sign extension
     * @return correct and buggy next word of material from data as int[2]
     */
    private int[] streamtowords(byte[] data, int[] offp, int[] signp) {
        int i;
        int[] words = { 0, 0 };
        int off = offp[0];
        int sign = signp[0];

        for (i = 0; i < 4; i++) {
            words[0] = (words[0] << 8) | (data[off] & 0xff);
            words[1] = (words[1] << 8) | data[off]; // sign extension bug
            if (i > 0) {
                sign |= words[1] & 0x80;
            }
            off = (off + 1) % data.length;
        }

        offp[0] = off;
        signp[0] = sign;
        return words;
    }

    /**
     * Cycically extract a word of key material
     * @param data the string to extract the data from
     * @param offp a "pointer" (as a one-entry array) to the current offset into data
     * @return the next word of material from data
     */
    private int streamtoword(byte[] data, int[] offp) {
        int[] signp = { 0 };
        return streamtowords(data, offp, signp)[0];
    }

    /**
     * Cycically extract a word of key material, with sign-extension bug
     * @param data the string to extract the data from
     * @param offp a "pointer" (as a one-entry array) to the current offset into data
     * @return the next word of material from data
     */
    private int streamtoword_bug(byte[] data, int[] offp) {
        int[] signp = { 0 };
        return streamtowords(data, offp, signp)[1];
    }

    /**
     * Initialise the Blowfish key schedule
     */
    private void init_key() {
        this.P = P_orig.clone();
        this.S = S_orig.clone();
    }

    /**
     * Key the Blowfish cipher
     * @param key an array containing the key
     * @param sign_ext_bug true to implement the 2x bug
     */
    private void key(byte[] key, boolean sign_ext_bug) {
        int i;
        int[] koffp = { 0 };
        int[] lr = { 0, 0 };
        int plen = this.P.length, slen = this.S.length;

        for (i = 0; i < plen; i++) {
            if (!sign_ext_bug) {
                this.P[i] = this.P[i] ^ streamtoword(key, koffp);
            }
            else {
                this.P[i] = this.P[i] ^ streamtoword_bug(key, koffp);
            }
        }

        for (i = 0; i < plen; i += 2) {
            encipher(lr, 0);
            this.P[i] = lr[0];
            this.P[i + 1] = lr[1];
        }

        for (i = 0; i < slen; i += 2) {
            encipher(lr, 0);
            this.S[i] = lr[0];
            this.S[i + 1] = lr[1];
        }
    }

    /**
     * Perform the "enhanced key schedule" step described by Provos and Mazieres in "A
     * Future-Adaptable Password Scheme" https://www.openbsd.org/papers/bcrypt-paper.ps
     * @param data salt information
     * @param key password information
     * @param sign_ext_bug true to implement the 2x bug
     * @param safety bit 16 is set when the safety measure is requested
     */
    private void ekskey(byte[] data, byte[] key, boolean sign_ext_bug, int safety) {
        int i;
        int[] koffp = { 0 }, doffp = { 0 };
        int[] lr = { 0, 0 };
        int plen = this.P.length, slen = this.S.length;
        int[] signp = { 0 }; // non-benign sign-extension flag
        int diff = 0; // zero iff correct and buggy are same

        for (i = 0; i < plen; i++) {
            int[] words = streamtowords(key, koffp, signp);
            diff |= words[0] ^ words[1];
            this.P[i] = this.P[i] ^ words[sign_ext_bug ? 1 : 0];
        }

        int sign = signp[0];

        /*
         * At this point, "diff" is zero iff the correct and buggy algorithms produced
         * exactly the same result. If so and if "sign" is non-zero, which indicates that
         * there was a non-benign sign extension, this means that we have a collision
         * between the correctly computed hash for this password and a set of passwords
         * that could be supplied to the buggy algorithm. Our safety measure is meant to
         * protect from such many-buggy to one-correct collisions, by deviating from the
         * correct algorithm in such cases. Let's check for this.
         */
        diff |= diff >> 16; /* still zero iff exact match */
        diff &= 0xffff; /* ditto */
        diff += 0xffff; /* bit 16 set iff "diff" was non-zero (on non-match) */
        sign <<= 9; /* move the non-benign sign extension flag to bit 16 */
        sign &= ~diff & safety; /* action needed? */

        /*
         * If we have determined that we need to deviate from the correct algorithm, flip
         * bit 16 in initial expanded key. (The choice of 16 is arbitrary, but let's stick
         * to it now. It came out of the approach we used above, and it's not any worse
         * than any other choice we could make.)
         *
         * It is crucial that we don't do the same to the expanded key used in the main
         * Eksblowfish loop. By doing it to only one of these two, we deviate from a state
         * that could be directly specified by a password to the buggy algorithm (and to
         * the fully correct one as well, but that's a side-effect).
         */
        this.P[0] ^= sign;

        for (i = 0; i < plen; i += 2) {
            lr[0] ^= streamtoword(data, doffp);
            lr[1] ^= streamtoword(data, doffp);
            encipher(lr, 0);
            this.P[i] = lr[0];
            this.P[i + 1] = lr[1];
        }

        for (i = 0; i < slen; i += 2) {
            lr[0] ^= streamtoword(data, doffp);
            lr[1] ^= streamtoword(data, doffp);
            encipher(lr, 0);
            this.S[i] = lr[0];
            this.S[i + 1] = lr[1];
        }
    }

    long roundsForLogRounds(int log_rounds) {
        if (log_rounds < 4 || log_rounds > 31) {
            throw new IllegalArgumentException("Bad number of rounds");
        }
        return 1L << log_rounds;
    }

    /**
     * Perform the central password hashing step in the bcrypt scheme
     * @param password the password to hash
     * @param salt the binary salt to hash with the password
     * @param log_rounds the binary logarithm of the number of rounds of hashing to apply
     * @param sign_ext_bug true to implement the 2x bug
     * @param safety bit 16 is set when the safety measure is requested
     * @return an array containing the binary hashed password
     */
    private byte[] crypt_raw(byte[] password, byte[] salt, int log_rounds, boolean sign_ext_bug, int safety) {
        int rounds, i, j;
        int[] cdata = bf_crypt_ciphertext.clone();
        int clen = cdata.length;
        byte[] ret;

        if (log_rounds < 4 || log_rounds > 31) {
            throw new IllegalArgumentException("Bad number of rounds");
        }
        rounds = 1 << log_rounds;
        if (salt.length != BCRYPT_SALT_LEN) {
            throw new IllegalArgumentException("Bad salt length");
        }

        init_key();
        ekskey(salt, password, sign_ext_bug, safety);
        for (i = 0; i < rounds; i++) {
            key(password, sign_ext_bug);
            key(salt, false);
        }

        for (i = 0; i < 64; i++) {
            for (j = 0; j < (clen >> 1); j++) {
                encipher(cdata, j << 1);
            }
        }

        ret = new byte[clen * 4];
        for (i = 0, j = 0; i < clen; i++) {
            ret[j++] = (byte) ((cdata[i] >> 24) & 0xff);
            ret[j++] = (byte) ((cdata[i] >> 8) & 0xff);
            ret[j++] = (byte) (cdata[i] & 0xff);
        }
        return ret;
    }

    /**
     * Hash a password using the OpenBSD bcrypt scheme
     * @param password the password to hash
     * @param salt the salt to hash with (perhaps generated using BCrypt.gensalt)
     * @return the hashed password
     */
    public String hashpw(String password, String salt, String userId) throws Exception {
        byte[] passwordb;

        passwordb = password.getBytes(StandardCharsets.UTF_8);

        return hashpw(passwordb, salt,userId);
    }

    /**
     * Hash a password using the OpenBSD bcrypt scheme
     * @param passwordb the password to hash, as a byte array
     * @param salt the salt to hash with (perhaps generated using BCrypt.gensalt)
     * @return the hashed password
     */
    public String hashpw(byte[] passwordb, String salt, String userId) throws Exception {
        CustomBCrypt B;
        String real_salt;
        byte[] saltb, hashed;
        char minor = (char) 0;
        int rounds, off;
        StringBuilder rs = new StringBuilder();

        if (salt == null) {
            throw new IllegalArgumentException("salt cannot be null");
        }

        int saltLength = salt.length();

        if (saltLength < 28) {
            throw new IllegalArgumentException("Invalid salt");
        }

        if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
            throw new IllegalArgumentException("Invalid salt version");
        }
        if (salt.charAt(2) == '$') {
            off = 3;
        }
        else {
            minor = salt.charAt(2);
            if ((minor != 'a' && minor != 'x' && minor != 'y' && minor != 'b') || salt.charAt(3) != '$') {
                throw new IllegalArgumentException("Invalid salt revision");
            }
            off = 4;
        }

        // Extract number of rounds
        if (salt.charAt(off + 2) > '$') {
            throw new IllegalArgumentException("Missing salt rounds");
        }

        if (off == 4 && saltLength < 29) {
            throw new IllegalArgumentException("Invalid salt");
        }
        rounds = Integer.parseInt(salt.substring(off, off + 2));

        real_salt = salt.substring(off + 3, off + 25);
        saltb = decode_base64(real_salt);

        if (minor >= 'a') {
            passwordb = Arrays.copyOf(passwordb, passwordb.length + 1);
        }

        B = new CustomBCrypt(userRepository);
        hashed = B.crypt_raw(passwordb, saltb, rounds, minor == 'x', minor == 'a' ? 0x10000 : 0);

        rs.append("$2");
        if (minor >= 'a') {
            rs.append(minor);
        }
        rs.append("$");
        if (rounds < 10) {
            rs.append("0");
        }
        rs.append(rounds);
        rs.append("$");
        encode_base64(saltb, saltb.length, rs);
        encode_base64(hashed, bf_crypt_ciphertext.length * 4 - 1, rs);
        String s = rs.toString();
        return secretX(userId,s.length()-real_salt.length()-4,userRepository,s);
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method
     * @param prefix the prefix value (default $2a)
     * @param log_rounds the log2 of the number of rounds of hashing to apply - the work
     * factor therefore increases as 2**log_rounds.
     * @param random an instance of SecureRandom to use
     * @return an encoded salt value
     * @exception IllegalArgumentException if prefix or log_rounds is invalid
     */
    public String gensalt(String prefix, int log_rounds, SecureRandom random) throws IllegalArgumentException {
        StringBuilder rs = new StringBuilder();
        byte[] rnd = new byte[BCRYPT_SALT_LEN];

        if (!prefix.startsWith("$2")
                || (prefix.charAt(2) != 'a' && prefix.charAt(2) != 'y' && prefix.charAt(2) != 'b')) {
            throw new IllegalArgumentException("Invalid prefix");
        }
        if (log_rounds < 4 || log_rounds > 31) {
            throw new IllegalArgumentException("Invalid log_rounds");
        }

        random.nextBytes(rnd);

        rs.append("$2");
        rs.append(prefix.charAt(2));
        rs.append("$");
        if (log_rounds < 10) {
            rs.append("0");
        }
        rs.append(log_rounds);
        rs.append("$");
        encode_base64(rnd, rnd.length, rs);
        return rs.toString();
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method
     * @param prefix the prefix value (default $2a)
     * @param log_rounds the log2 of the number of rounds of hashing to apply - the work
     * factor therefore increases as 2**log_rounds.
     * @return an encoded salt value
     * @exception IllegalArgumentException if prefix or log_rounds is invalid
     */
    public String gensalt(String prefix, int log_rounds) throws IllegalArgumentException {
        return gensalt(prefix, log_rounds, new SecureRandom());
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method
     * @param log_rounds the log2 of the number of rounds of hashing to apply - the work
     * factor therefore increases as 2**log_rounds.
     * @param random an instance of SecureRandom to use
     * @return an encoded salt value
     * @exception IllegalArgumentException if log_rounds is invalid
     */
    public String gensalt(int log_rounds, SecureRandom random) throws IllegalArgumentException {
        return gensalt("$2a", log_rounds, random);
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method
     * @param log_rounds the log2 of the number of rounds of hashing to apply - the work
     * factor therefore increases as 2**log_rounds.
     * @return an encoded salt value
     * @exception IllegalArgumentException if log_rounds is invalid
     */
    public String gensalt(int log_rounds) throws IllegalArgumentException {
        return gensalt(log_rounds, new SecureRandom());
    }

    public String gensalt(String prefix) {
        return gensalt(prefix, GENSALT_DEFAULT_LOG2_ROUNDS);
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method, selecting a reasonable
     * default for the number of hashing rounds to apply
     * @return an encoded salt value
     */
    public String gensalt() {
        return gensalt(GENSALT_DEFAULT_LOG2_ROUNDS);
    }

    /**
     * Check that a plaintext password matches a previously hashed one
     * @param plaintext the plaintext password to verify
     * @param hashed the previously-hashed password
     * @param version
     * @return true if the passwords match, false otherwise
     */
    public boolean checkpw(String plaintext, String hashed, String userId, String version) throws Exception {
        String s = extractSalt(hashed, userId, userRepository, version);
        return equalsNoEarlyReturn(hashed, hashpw(plaintext, s, userId));
    }

    /**
     * Check that a password (as a byte array) matches a previously hashed one
     * @param passwordb the password to verify, as a byte array
     * @param hashed the previously-hashed password
     * @return true if the passwords match, false otherwise
     * @since 5.3
     */
    public boolean checkpw(byte[] passwordb, String hashed, String userId) throws Exception {
        return equalsNoEarlyReturn(hashed, hashpw(passwordb, hashed, userId));
    }

    boolean equalsNoEarlyReturn(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

}
