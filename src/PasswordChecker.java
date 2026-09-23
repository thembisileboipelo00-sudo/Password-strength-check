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

