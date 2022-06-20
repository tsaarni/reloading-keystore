package keystore_tutorial;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class PemReader {

    private static final String PEM_START = "-----BEGIN ";
    private static final String PEM_END = "-----END ";
    private static final String PEM_END_OF_LINE = "-----";

    // Parser state.
    private boolean isInsideBlock = false;
    BufferedReader reader;

    PemReader(Path p) throws IOException {
        reader = new BufferedReader(new InputStreamReader(Files.newInputStream(p)));
    }

    PemReader(byte[] data) {
        ByteArrayInputStream stream = new ByteArrayInputStream(data);
        InputStreamReader streamReader = new InputStreamReader(stream, StandardCharsets.UTF_8);
        reader = new BufferedReader(streamReader);
    }

    public Block decode() throws IOException {
        String line;
        String type = "";
        StringBuilder builder = new StringBuilder();

        while ((line = reader.readLine()) != null) {
            if (line.startsWith(PEM_START)) {
                isInsideBlock = true;
                type = parseType(line);
            } else if (isInsideBlock && line.startsWith(PEM_END)) {
                isInsideBlock = false;
                byte[] encoded = String.valueOf(builder).getBytes();
                return new Block(type, Base64.getMimeDecoder().decode(encoded));
            } else if (isInsideBlock) {
                builder.append(line);
            }
        }

        return null;
    }

    /**
     * Parse block type from the header, for example
     * -----BEGIN PRIVATE KEY-----
     * Returns PRIVATE KEY
     */
    private String parseType(String line) {
        int start = PEM_START.length();
        int end = line.lastIndexOf(PEM_END_OF_LINE);
        return line.substring(start, end);
    }

    public class Block {
        private final String type;
        private final byte[] bytes;

        Block(String type, byte[] bytes){
            this.type = type;
            this.bytes = bytes;
        }

        public String getType() {
            return type;
        }

        public byte[] getBytes() {
            return bytes;
        }
    }
}
