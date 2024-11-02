public class ApiKeyGenerator {

    private final String boardSerial;
    private final String macAddress;
    private final long time;

    public ApiKeyGenerator(String boardSerial, String macAddress, long time) {
        this.boardSerial = boardSerial;
        this.macAddress = macAddress;
        this.time = time; // Use the provided time value
    }

    public static char transformChar(char c1, char c2) {
        int result = (c1 ^ c2) & 127;
        if (result < 48) {
            result = (result % 26) + 97; // Lowercase letters
        } else if (result > 57 && result < 65) {
            result = (result % 26) + 65; // Uppercase letters
        } else if (result > 90 && result < 97) {
            result = (result % 10) + 48; // Digits
        } else if (result > 122) {
            result = (result % 10) + 48;
        }
        return (char) result;
    }

    public String generateApiKey() {
        // Initialize the 64-character key template string
        char[] keyTemplate = "n4W2lNnb2IPnfBrXwSTzTlvmDvsbemYRvXBRWrfNtQJlMiQ8yPVRmGcoPd7szSu2".toCharArray();

        // Step 1: Apply MAC address to the first 32 characters
        for (int i = 0; i < Math.min(macAddress.length(), 32); i++) {
            keyTemplate[i] = transformChar(keyTemplate[i], macAddress.charAt(i));
        }

        // Step 2: Apply board serial to the next 32 characters
        for (int i = 0; i < Math.min(boardSerial.length(), 32); i++) {
            keyTemplate[i + 32] = transformChar(keyTemplate[i + 32], boardSerial.charAt(i));
        }

        // Step 3: Apply time-based transformations
        long adjustedTime = time / 86400; // Convert time to daily increments
        for (int i = 0; i < 16; i++) {
            if ((adjustedTime & (1 << i)) != 0) {
                int idx = i * 4;
                keyTemplate[idx] = transformChar(keyTemplate[idx], keyTemplate[i * 2 + 32]);
                keyTemplate[idx + 1] = transformChar(keyTemplate[idx + 1], keyTemplate[63 - (i * 2)]);
                keyTemplate[idx + 2] = transformChar(keyTemplate[idx], keyTemplate[idx + 1]);
                keyTemplate[idx + 3] = transformChar(keyTemplate[idx + 1], keyTemplate[idx + 2]);
            }
        }

        return new String(keyTemplate);
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java ApiKeyGenerator <time> <boardSerial> <macAddress>");
            System.exit(1);
        }

        try {
            long time = Long.parseLong(args[0]);
            String boardSerial = args[1];
            String macAddress = args[2];

            ApiKeyGenerator generator = new ApiKeyGenerator(boardSerial, macAddress, time);
            
            // Print the provided time in seconds
            System.out.println("Provided time (seconds since epoch): " + time);
            
            // Generate and print the API key
            String apiKey = generator.generateApiKey();
            System.out.println("Generated API Key: " + apiKey);
        } catch (NumberFormatException e) {
            System.out.println("Invalid time format. Please enter a valid number for time.");
            System.exit(1);
        }
    }
}

