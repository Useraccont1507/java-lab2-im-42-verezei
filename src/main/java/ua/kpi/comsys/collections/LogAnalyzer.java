package ua.kpi.comsys.collections;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes server log lines in Common Log Format:
 * {@code host ident authuser [date] "request" status bytes}.
 */
public class LogAnalyzer {

    private static final Pattern CLF_LINE = Pattern.compile(
            "^(\\S+) \\S+ \\S+ "
                    + "\\[\\d{2}/[A-Za-z]{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2} [+-]\\d{4}] "
                    + "\"[^\"]*\" "
                    + "\\d{3} "
                    + "(\\d+|-)$");

    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");

    public Set<String> getUniqueIps(List<String> logLines) {
        requireLines(logLines);
        Set<String> ips = new HashSet<>();
        for (String line : logLines) {
            String ip = extractIp(line);
            if (ip != null) {
                ips.add(ip);
            }
        }
        return ips;
    }

    private static void requireLines(List<String> logLines) {
        if (logLines == null) {
            throw new IllegalArgumentException("logLines cannot be null");
        }
    }

    /** Returns the client IP of a valid CLF line, or {@code null} if the line is malformed. */
    private static String extractIp(String line) {
        if (line == null) {
            return null;
        }
        Matcher matcher = CLF_LINE.matcher(line.strip());
        if (!matcher.matches()) {
            return null;
        }
        String ip = matcher.group(1);
        return IPV4.matcher(ip).matches() ? ip : null;
    }
}
