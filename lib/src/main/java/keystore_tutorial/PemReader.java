/*
 * Copyright Tero Saarni
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package keystore_tutorial;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/**
 * Implements support for reading PEM encoded files and PEM bundles.
 */
public class PemReader {

    private static final String PEM_START = "-----BEGIN ";
    private static final String PEM_END = "-----END ";
    private static final String PEM_END_OF_LINE = "-----";

    // Parser state.
    private boolean isInsideBlock = false;
    BufferedReader reader;

    /**
     * Constructs new reader to parse PEM block(s) from a file.
     *
     * @param path Path to PEM file.
     */
    PemReader(Path path) throws IOException {
        reader = new BufferedReader(new InputStreamReader(Files.newInputStream(path)));
    }

    /**
     * Constructs new reader to parse PEM block(s) from byte array.
     *
     * @param data Buffer containing PEM block(s).
     */
    PemReader(byte[] data) {
        ByteArrayInputStream stream = new ByteArrayInputStream(data);
        InputStreamReader streamReader = new InputStreamReader(stream, StandardCharsets.UTF_8);
        reader = new BufferedReader(streamReader);
    }

    /**
     * Decodes next PEM block.
     *
     * @return Decoded data or null if no more PEM blocks can be decoded.
     */
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
     * Parse block type from PEM header.
     * For example if header is {@code -----BEGIN PRIVATE KEY-----} then return {@code "PRIVATE KEY"}.
     */
    private String parseType(String line) {
        int start = PEM_START.length();
        int end = line.lastIndexOf(PEM_END_OF_LINE);
        return line.substring(start, end);
    }

    /**
     * Represents PEM block, that is, the content from PEM file that is enclosed between
     * {@code -----BEGIN [TYPE]-----} and {@code -----END [TYPE]-----} headers.
     */
    public class Block {
        private final String type;
        private final byte[] bytes;

        Block(String type, byte[] bytes) {
            this.type = type;
            this.bytes = bytes;
        }

        /**
         * Get type from PEM header.
         * For example "CERTIFICATE" or "PRIVATE KEY"
         */
        public String getType() {
            return type;
        }

        /**
         * Get bytes from the decoded PEM block.
         */
        public byte[] getBytes() {
            return bytes;
        }
    }

}
