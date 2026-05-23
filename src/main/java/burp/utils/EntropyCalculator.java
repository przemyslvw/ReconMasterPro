package burp.utils;

import java.util.HashMap;
import java.util.Map;

public class EntropyCalculator {

    public static double calculate(String value) {
        if (value == null || value.isEmpty()) return 0.0;

        Map<Character, Integer> freq = new HashMap<>();
        for (char c : value.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }

        double entropy = 0.0;
        int len = value.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
