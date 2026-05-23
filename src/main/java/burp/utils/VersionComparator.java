package burp.utils;

public class VersionComparator {

    public static boolean isVulnerable(String detected, String affectedBefore) {
        if (affectedBefore == null) return false;
        if (detected == null) return true;  // conservative: nieznana wersja = podatna

        int[] d = parse(detected);
        int[] b = parse(affectedBefore);

        // wypełnij krótszą tablicę zerami
        int len = Math.max(d.length, b.length);
        d = pad(d, len);
        b = pad(b, len);

        for (int i = 0; i < len; i++) {
            if (d[i] < b[i]) return true;
            if (d[i] > b[i]) return false;
        }
        return false; // d == b → bezpieczna (affected_before = exclusive)
    }

    private static int[] parse(String version) {
        String[] parts = version.split("[.\\-]");
        int[] nums = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                nums[i] = Integer.parseInt(parts[i].replaceAll("[^0-9]", ""));
            } catch (NumberFormatException e) {
                nums[i] = 0;
            }
        }
        return nums;
    }

    private static int[] pad(int[] arr, int len) {
        if (arr.length == len) return arr;
        int[] padded = new int[len];
        System.arraycopy(arr, 0, padded, 0, arr.length);
        return padded;
    }
}
