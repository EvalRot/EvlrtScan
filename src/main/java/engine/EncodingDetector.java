package engine;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Detects the encoding format of an HTTP parameter value.
 * Priority order: BASE64_URL_ENCODED → URL_ENCODED → BASE64 → UNICODE → PLAIN
 */
public class EncodingDetector {

    public enum Encoding {
        PLAIN,
        URL_ENCODED,
        BASE64,
        BASE64_URL_ENCODED,
        UNICODE
    }

    private static final Pattern URL_ENCODED_PATTERN = Pattern.compile("%[0-9A-Fa-f]{2}");
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]{4,}={0,2}$");
    private static final Pattern UNICODE_PATTERN = Pattern.compile("\\\\u[0-9A-Fa-f]{4}");

    /**
     * Detects the encoding of a parameter value.
     */
    public static Encoding detect(String value) {
        if (value == null || value.isEmpty())
            return Encoding.PLAIN;

        // 1. Check for URL-encoded content (may wrap base64)
        if (URL_ENCODED_PATTERN.matcher(value).find()) {
            try {
                String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
                if (!decoded.equals(value) && isValidBase64(decoded)) {
                    return Encoding.BASE64_URL_ENCODED;
                }
            } catch (Exception ignored) {
            }
            return Encoding.URL_ENCODED;
        }

        // 2. Check for pure base64
        if (isValidBase64(value))
            return Encoding.BASE64;

        // 3. Check for unicode escape sequences
        if (UNICODE_PATTERN.matcher(value).find())
            return Encoding.UNICODE;

        // 4. Default
        return Encoding.PLAIN;
    }

    /**
     * Checks if the string is valid base64 with strict heuristics
     * to avoid false positives on plain text values.
     *
     * Rules:
     * - Minimum 8 characters (short strings like "Abcd" are too ambiguous)
     * - Length must be divisible by 4 (real base64 always is, with padding)
     * - Short strings (under 24 chars) MUST have padding ('=') — this
     * eliminates "test1234", "admin123" etc.
     * - Decoded result must be 90%+ printable (rejects binary garbage)
     * - Decoded result must differ from input
     */
    private static boolean isValidBase64(String value) {
        if (value.length() < 8)
            return false;

        // Base64 output length is always divisible by 4
        if (value.length() % 4 != 0)
            return false;

        if (!BASE64_PATTERN.matcher(value).matches())
            return false;

        // For short strings, require padding — real base64 almost always
        // has it unless input length was exactly divisible by 3.
        // Plain text like "testtest" would never have trailing '='
        if (value.length() < 24 && !value.endsWith("="))
            return false;

        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            String decodedStr = new String(decoded, StandardCharsets.UTF_8);
            return !decodedStr.equals(value) && isPrintableText(decodedStr);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Heuristic: decoded base64 should be mostly printable characters.
     * 90% threshold to reject binary-looking garbage.
     */
    private static boolean isPrintableText(String s) {
        if (s.isEmpty())
            return false;
        int printable = 0;
        for (char c : s.toCharArray()) {
            if (c >= 0x20 && c < 0x7F || c == '\n' || c == '\r' || c == '\t')
                printable++;
        }
        return printable >= s.length() * 0.9;
    }
}
