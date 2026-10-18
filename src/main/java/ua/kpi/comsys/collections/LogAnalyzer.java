package ua.kpi.comsys.collections;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

    /**
     * Returns up to {@code topN} most frequent IPs, sorted by frequency descending;
     * IPs with equal frequency are sorted lexicographically ascending.
     */
    public List<String> getTopIps(List<String> logLines, int topN) {
        requireLines(logLines);
        if (topN <= 0) {
            throw new IllegalArgumentException("topN must be greater than 0");
        }

        Map<String, Integer> counts = new HashMap<>();
        for (String line : logLines) {
            String ip = extractIp(line);
            if (ip != null) {
                counts.merge(ip, 1, Integer::sum);
            }
        }

        List<Map.Entry<String, Integer>> entries = new ArrayList<>(counts.entrySet());
        entries.sort(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                .thenComparing(Map.Entry.comparingByKey()));

        List<String> top = new ArrayList<>();
        for (int i = 0; i < Math.min(topN, entries.size()); i++) {
            top.add(entries.get(i).getKey());
        }
        return top;
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
