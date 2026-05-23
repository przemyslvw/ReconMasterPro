package burp;

import burp.utils.EntropyCalculator;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EntropyCalculatorTest {

    @Test
    void singleCharRepeatedHasZeroEntropy() {
        assertEquals(0.0, EntropyCalculator.calculate("aaaaaaaaaa"), 0.01);
    }

    @Test
    void twoAlternatingCharsHasEntropy1() {
        // "ababab..." — 2 równo-prawdopodobne symbole → H = 1.0
        assertEquals(1.0, EntropyCalculator.calculate("ababababab"), 0.01);
    }

    @Test
    void highlyRandomStringHasHighEntropy() {
        // typowy token AWS / GitHub — entropia > 4.5
        double h = EntropyCalculator.calculate("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assertTrue(h > 4.5, "Oczekiwano > 4.5, got " + h);
    }

    @Test
    void emptyStringReturnsZero() {
        assertEquals(0.0, EntropyCalculator.calculate(""), 0.001);
    }

    @Test
    void nullReturnsZero() {
        assertEquals(0.0, EntropyCalculator.calculate(null), 0.001);
    }

    @Test
    void shortLowercaseAlphaHasModerateEntropy() {
        // "abcdefgh" — 8 różnych znaków, każdy raz → H = 3.0
        double h = EntropyCalculator.calculate("abcdefgh");
        assertTrue(h > 2.5 && h < 3.5, "Oczekiwano ~3.0, got " + h);
    }
}
