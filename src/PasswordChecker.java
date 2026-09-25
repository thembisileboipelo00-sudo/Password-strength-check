import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

/**
 * A beginner cybersecurity project that evaluates password strength using
 * two independent checks:
 *
 *   1. Entropy estimation  - how hard the password would be to brute-force,
 *      based on character-set size and length (information theory approach).
 *   2. Breach list lookup  - whether the exact password appears in a local
 *      file of commonly leaked passwords (offline, no network calls -
 *      this keeps the tool safe to run and avoids sending real passwords
 *      anywhere).
 *
 * Design decision: entropy and breach-checking are deliberately kept as
 * SEPARATE checks rather than merged into one score. A password can be
 * high-entropy but still breached (e.g. it appeared in a leak despite being
 * "random looking"), so a single blended score would hide that risk.
 */
public class PasswordChecker {

    private static final String BREACH_FILE = "../data/breached_passwords.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a password to check: ");
        String password = scanner.nextLine();

        double entropy = calculateEntropy(password);
        System.out.printf("Entropy: %.2f bits%n", entropy);
        System.out.println("Strength: " + rateStrength(entropy));

        boolean breached = isBreached(password);
        if (breached) {
            System.out.println("WARNING: This password appears in a known breach list.");
        } else {
            System.out.println("Not found in local breach list.");
        }

        scanner.close();
    }

    static double calculateEntropy(String password) {
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
        if (hasSymbol) poolSize += 32;

        if (poolSize == 0 || password.isEmpty()) return 0.0;

        return password.length() * (Math.log(poolSize) / Math.log(2));
    }

    static String rateStrength(double entropy) {
        if (entropy < 28) return "Very Weak";
        if (entropy < 36) return "Weak";
        if (entropy < 60) return "Reasonable";
        if (entropy < 128) return "Strong";
        return "Very Strong";
    }

    static boolean isBreached(String password) {
        Set<String> breachedPasswords = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(BREACH_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                breachedPasswords.add(line.trim());
            }
        } catch (IOException e) {
            System.out.println("(Could not read breach list: " + e.getMessage() + ")");
            return false;
        }
        return breachedPasswords.contains(password);
    }
}
