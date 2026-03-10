package engine;

import engine.EncodingDetector.Encoding;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Encodes and decodes parameter values in various formats.
 * Used by PayloadInjector to preserve the original encoding when injecting
 * payloads.
 */
public class PayloadEncoder {

    /**
     * Decode an encoded value back to plain text.
     */
    public static String decode(String value, Encoding encoding) {
        if (value == null)
            return "";

        return switch (encoding) {
            case PLAIN -> value;
            case URL_ENCODED -> {
                try {
                    yield URLDecoder.decode(value, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    yield value;
                }
            }
            case BASE64 -> {
                try {
                    yield new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    yield value;
                }
            }
            case BASE64_URL_ENCODED -> {
                try {
                    String urlDecoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
                    yield new String(Base64.getDecoder().decode(urlDecoded), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    yield value;
                }
            }
            case UNICODE -> unescapeUnicode(value);
        };
    }

    /**
     * Encode a plain text value into the specified format.
     */
    public static String encode(String plainValue, Encoding encoding) {
        if (plainValue == null)
            return "";

        return switch (encoding) {
            case PLAIN -> plainValue;
            case URL_ENCODED -> URLEncoder.encode(plainValue, StandardCharsets.UTF_8);
            case BASE64 -> Base64.getEncoder().encodeToString(
                    plainValue.getBytes(StandardCharsets.UTF_8));
            case BASE64_URL_ENCODED -> URLEncoder.encode(
                    Base64.getEncoder().encodeToString(
                            plainValue.getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8);
            case UNICODE -> toUnicode(plainValue);
        };
    }

    /**
     * Convert a string to Unicode escape sequences ({@code \\uXXXX}).
     * All characters are escaped — useful for JSON WAF bypass.
     */
    public static String toUnicode(String value) {
        if (value == null)
            return "";
        StringBuilder sb = new StringBuilder();
        for (char c : value.toCharArray()) {
            sb.append(String.format("\\u%04x", (int) c));
        }
        return sb.toString();
    }

    /**
     * Unescape {@code \\uXXXX} sequences back to characters.
     */
    private static String unescapeUnicode(String value) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < value.length()) {
            if (i + 5 < value.length() && value.charAt(i) == '\\' && value.charAt(i + 1) == 'u') {
                try {
                    int cp = Integer.parseInt(value.substring(i + 2, i + 6), 16);
                    sb.append((char) cp);
                    i += 6;
                    continue;
                } catch (NumberFormatException ignored) {
                }
            }
            sb.append(value.charAt(i));
            i++;
        }
        return sb.toString();
    }
}
