package burp;

import burp.utils.VersionComparator;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class VersionComparatorTest {

    @Test
    void olderVersionIsVulnerable() {
        // jQuery 1.9.0 < 3.4.0 → podatny
        assertTrue(VersionComparator.isVulnerable("1.9.0", "3.4.0"));
    }

    @Test
    void exactBoundaryIsNotVulnerable() {
        // "affected_before 3.4.0" → wersja 3.4.0 jest już bezpieczna
        assertFalse(VersionComparator.isVulnerable("3.4.0", "3.4.0"));
    }

    @Test
    void newerVersionIsNotVulnerable() {
        assertFalse(VersionComparator.isVulnerable("3.6.1", "3.4.0"));
    }

    @Test
    void nullVersionReturnsTrueConservatively() {
        // nie wiemy wersji → zakładamy podatność (conservative)
        assertTrue(VersionComparator.isVulnerable(null, "3.4.0"));
    }

    @Test
    void nullAffectedBeforeReturnsFalse() {
        // null = brak ograniczenia wersji w CVE → nie oceniamy
        assertFalse(VersionComparator.isVulnerable("1.0.0", null));
    }

    @Test
    void majorVersionDifference() {
        assertTrue(VersionComparator.isVulnerable("2.99.99", "3.0.0"));
    }
}
