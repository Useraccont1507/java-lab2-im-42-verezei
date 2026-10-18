package ua.kpi.comsys.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class LogAnalyzerTest {

    private final LogAnalyzer analyzer = new LogAnalyzer();

    private static String line(String ip) {
        return ip + " ident alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481";
    }

    @Nested
    class GetUniqueIps {

        @Test
        void nullListThrows() {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getUniqueIps(null));
            assertEquals("logLines cannot be null", e.getMessage());
        }

        @Test
        void emptyListGivesEmptySet() {
            assertTrue(analyzer.getUniqueIps(List.of()).isEmpty());
        }

        @Test
        void sampleLineFromSpec() {
            String sample = "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] "
                    + "\"GET /index.html HTTP/1.1\" 200 9481";
            assertEquals(Set.of("127.0.0.1"), analyzer.getUniqueIps(List.of(sample)));
        }

        @Test
        void duplicatesCollapsed() {
            List<String> lines = List.of(line("10.0.0.1"), line("10.0.0.2"), line("10.0.0.1"));
            assertEquals(Set.of("10.0.0.1", "10.0.0.2"), analyzer.getUniqueIps(lines));
        }

        @Test
        void dashBytesAndDashIdentAccepted() {
            String l = "192.168.1.5 - - [10/Oct/2000:13:55:36 -0700] \"GET /a.gif HTTP/1.0\" 304 -";
            assertEquals(Set.of("192.168.1.5"), analyzer.getUniqueIps(List.of(l)));
        }

        @Test
        void surroundingWhitespaceIgnored() {
            assertEquals(Set.of("8.8.8.8"), analyzer.getUniqueIps(List.of("  " + line("8.8.8.8") + "\n")));
        }

        @Test
        void nullLineInsideListIgnored() {
            List<String> lines = new ArrayList<>(Arrays.asList(line("1.1.1.1"), null));
            assertEquals(Set.of("1.1.1.1"), analyzer.getUniqueIps(lines));
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "",
                "   ",
                "garbage",
                "127.0.0.1",
                // missing fields
                "127.0.0.1 ident [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1",
                "127.0.0.1 ident alice \"GET / HTTP/1.1\" 200 1",
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200",
                // broken date
                "127.0.0.1 ident alice [2025-05-01 07:20:10] \"GET / HTTP/1.1\" 200 1",
                "127.0.0.1 ident alice [01/May/2025:07:20:10] \"GET / HTTP/1.1\" 200 1",
                // request not quoted
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] GET / HTTP/1.1 200 1",
                // bad status / bytes
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 20 1",
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 abc",
                // trailing junk
                "127.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1 extra",
                // invalid IP
                "256.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1",
                "1.2.3 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1",
                "01.2.3.4 ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1",
                "example.com ident alice [01/May/2025:07:20:10 +0000] \"GET / HTTP/1.1\" 200 1"
        })
        void malformedLinesIgnored(String malformed) {
            List<String> lines = List.of(malformed, line("9.9.9.9"));
            assertEquals(Set.of("9.9.9.9"), analyzer.getUniqueIps(lines));
        }

        @Test
        void boundaryOctetsAccepted() {
            List<String> lines = List.of(line("0.0.0.0"), line("255.255.255.255"), line("199.249.100.9"));
            assertEquals(Set.of("0.0.0.0", "255.255.255.255", "199.249.100.9"), analyzer.getUniqueIps(lines));
        }
    }

    @Nested
    class GetTopIps {

        private List<String> repeat(String ip, int times) {
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < times; i++) {
                lines.add(line(ip));
            }
            return lines;
        }

        @Test
        void nullListThrows() {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getTopIps(null, 3));
            assertEquals("logLines cannot be null", e.getMessage());
        }

        @Test
        void nullListCheckedBeforeTopN() {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getTopIps(null, 0));
            assertEquals("logLines cannot be null", e.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
        void nonPositiveTopNThrows(int topN) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> analyzer.getTopIps(List.of(line("1.1.1.1")), topN));
            assertEquals("topN must be greater than 0", e.getMessage());
        }

        @Test
        void emptyListGivesEmptyResult() {
            assertEquals(List.of(), analyzer.getTopIps(List.of(), 5));
        }

        @Test
        void sortedByFrequencyDescending() {
            List<String> lines = new ArrayList<>();
            lines.addAll(repeat("10.0.0.1", 1));
            lines.addAll(repeat("10.0.0.2", 3));
            lines.addAll(repeat("10.0.0.3", 2));
            assertEquals(List.of("10.0.0.2", "10.0.0.3", "10.0.0.1"), analyzer.getTopIps(lines, 3));
        }

        @Test
        void topNLimitsResult() {
            List<String> lines = new ArrayList<>();
            lines.addAll(repeat("10.0.0.1", 5));
            lines.addAll(repeat("10.0.0.2", 4));
            lines.addAll(repeat("10.0.0.3", 3));
            assertEquals(List.of("10.0.0.1", "10.0.0.2"), analyzer.getTopIps(lines, 2));
        }

        @Test
        void tiesBrokenLexicographically() {
            List<String> lines = List.of(
                    line("192.168.0.1"), line("10.0.0.5"), line("172.16.0.1"),
                    line("172.16.0.1"), line("10.0.0.5"), line("192.168.0.1"));
            assertEquals(List.of("10.0.0.5", "172.16.0.1", "192.168.0.1"), analyzer.getTopIps(lines, 3));
        }

        @Test
        void tieBreakingIsStringOrderNotNumeric() {
            List<String> lines = List.of(line("9.0.0.1"), line("10.0.0.1"));
            assertEquals(List.of("10.0.0.1", "9.0.0.1"), analyzer.getTopIps(lines, 2));
        }

        @Test
        void tieAtCutoffKeepsAlphabeticallyFirst() {
            List<String> lines = new ArrayList<>();
            lines.addAll(repeat("5.5.5.5", 3));
            lines.addAll(repeat("3.3.3.3", 1));
            lines.addAll(repeat("2.2.2.2", 1));
            lines.addAll(repeat("4.4.4.4", 1));
            assertEquals(List.of("5.5.5.5", "2.2.2.2"), analyzer.getTopIps(lines, 2));
        }

        @Test
        void fewerUniqueIpsThanTopNReturnsAll() {
            List<String> lines = new ArrayList<>();
            lines.addAll(repeat("1.1.1.1", 1));
            lines.addAll(repeat("2.2.2.2", 2));
            assertEquals(List.of("2.2.2.2", "1.1.1.1"), analyzer.getTopIps(lines, 10));
        }

        @Test
        void malformedLinesNotCounted() {
            List<String> lines = new ArrayList<>(Arrays.asList(
                    line("1.1.1.1"),
                    "2.2.2.2 garbage",
                    "2.2.2.2 garbage",
                    null,
                    line("300.1.1.1")));
            assertEquals(List.of("1.1.1.1"), analyzer.getTopIps(lines, 5));
        }

        @Test
        void resultIsModifiable() {
            List<String> top = analyzer.getTopIps(List.of(line("1.1.1.1")), 1);
            top.add("x");
            assertEquals(2, top.size());
        }
    }
}
