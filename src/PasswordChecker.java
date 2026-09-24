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

