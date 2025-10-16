package com.example.app.util;

public class ByteFormat {
    
    /**
     * Truncates a Base64 or Hex string to show only first 24 and last 8 characters
     * @param data The data string to truncate
     * @return Truncated string with "..." in the middle if needed
     */
    public static String truncate(String data) {
        if (data == null) return "";
        if (data.length() <= 32) return data;
        return data.substring(0, 24) + "..." + data.substring(data.length() - 8);
    }

    /**
     * Formats bytes as human-readable size
     */
    public static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024));
    }

    /**
     * Converts hex string to readable format with spaces
     */
    public static String formatHex(String hex) {
        if (hex == null || hex.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) sb.append(" ");
            sb.append(hex.substring(i, Math.min(i + 2, hex.length())));
        }
        return sb.toString().toUpperCase();
    }
}
