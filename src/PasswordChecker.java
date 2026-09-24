import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

/**
 * PasswordChecker
 * ----------------
 * A beginner cybersecurity project that evaluates password strength using
 * two independent checks:
 *
 *   1. Entropy estimation  — how hard the password would be to brute-force,
 *      based on character-set size and length (information theory approach).
 *   2. Breach list lookup  — whether the exact password appears in a local
 *      file of commonly leaked passwords (offline, no network calls —
 *      this keeps the tool safe to run and avoids sending real passwords
 *      anywhere).
 *
 * Design decision: entropy and breach-checking are deliberately kept as
 * SEPARATE checks rather than merged into one score. A password can be
 * high-entropy but still breached (e.g. it appeared in a leak despite being
 * "random looking"), so a single blended score would hide that risk.
 */
public class PasswordChecker {

    private static final String BREACH_LIST_PATH = "data/common_passwords.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Password Strength & Breach Checker ===");
        System.out.println("(Nothing you type here is stored or sent anywhere.)\n");

        Set<String> breachedPasswords = loadBreachList(BREACH_LIST_PATH);

        System.out.print("Enter a password to test: ");
        String password = scanner.nextLine();

        double entropy = calculateEntropyBits(password);
        String strengthLabel = classifyStrength(entropy);
        boolean isBreached = breachedPasswords.contains(password.toLowerCase());

        System.out.println("\n--- Results ---");
        System.out.printf("Length:            %d characters%n", password.length());
        System.out.printf("Estimated entropy: %.1f bits%n", entropy);
        System.out.printf("Strength rating:   %s%n", strengthLabel);
        System.out.printf("Found in breach list: %s%n", isBreached ? "YES — do not use this password" : "No match found locally");

        printSuggestions(password, entropy, isBreached);

        scanner.close();
    }
       /**
     * Estimates password entropy in bits using the standard formula:
     *   entropy = length * log2(poolSize)
     * where poolSize is the size of the character set the password draws from.
     * This is a simplification (it assumes random selection from the pool,
     * which real human-chosen passwords rarely are) — that limitation is
     * called out in the README rather than hidden.
     */
    public static double calculateEntropyBits(String password) {
        if (password == null || password.isEmpty()) {
            return 0.0;
        }

        int poolSize = 0;
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;

        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSymbol = true;
        }

        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSymbol) poolSize += 32; // approx. printable ASCII symbols

        if (poolSize == 0) return 0.0;

        return password.length() * (Math.log(poolSize) / Math.log(2));
    }
       /**
     * Converts a raw entropy value into a human-readable strength label.
     * Thresholds are based on commonly cited guidance (e.g. NIST-adjacent
     * rules of thumb): under 28 bits is very weak, 60+ is strong.
     */
    public static String classifyStrength(double entropyBits) {
        if (entropyBits < 28) return "Very Weak";
        if (entropyBits < 36) return "Weak";
        if (entropyBits < 60) return "Reasonable";
        if (entropyBits < 128) return "Strong";
        return "Very Strong";
    }
