package ru.blackfan.bfscan.parsing.constants;

import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourcesLoader;
import jadx.api.ResourceType;
import jadx.core.utils.exceptions.JadxException;
import jadx.core.xmlgen.ResContainer;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.XMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.blackfan.bfscan.config.ConfigLoader;
import ru.blackfan.bfscan.helpers.Helpers;
import ru.blackfan.bfscan.helpers.KeyValuePair;
import ru.blackfan.bfscan.parsing.constants.file.ApkResources;
import ru.blackfan.bfscan.parsing.constants.file.Class;
import ru.blackfan.bfscan.parsing.constants.file.Properties;
import ru.blackfan.bfscan.parsing.constants.file.Xml;
import ru.blackfan.bfscan.parsing.constants.file.Yml;

public class ConstantsProcessor {

    private static final Logger logger = LoggerFactory.getLogger(ConstantsProcessor.class);

    private final JadxDecompiler jadx;
    private final PrintWriter writerUrlsPaths;
    private final PrintWriter writerSecrets;
    private final PrintWriter writerSearch;
    private static final double ENTROPY_THRESHOLD = 4.1;
    private static final double ENTROPY_THRESHOLD_MIN = 3.9;
    private static final List<String> SECRET_KEYWORDS = Arrays.asList("api", "secret", "token", "auth", "pass", "password", "pwd", "hash", "salt", "crypt", "cert", "sign", "credential");
    private static final Pattern INVALID_CONTROL_CHARS_PATTERN = Pattern.compile("[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F]", Pattern.DOTALL);
    private static final Pattern URL_PATTERN = Pattern.compile("(\\bhttps?)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]");
    private static final Pattern QUOTE_PATTERN = Pattern.compile("['\"`](.*?)['\"`]");
    private final Set<String> urls = new LinkedHashSet<>();
    private final Set<String> paths = new LinkedHashSet<>();
    private final Set<String> searchResults = new LinkedHashSet<>();
    private final Map<String, Set<String>> secrets = new LinkedHashMap<>();
    private final DocumentBuilderFactory factory;
    public static final String EXCLUDED_SECRETS_REGEXP = ConfigLoader.getExcludedSecretsRegexp();
    public static final String EXCLUDED_LINKS_REGEXP = ConfigLoader.getExcludedLinksRegexp();

    public ConstantsProcessor(JadxDecompiler jadx, PrintWriter writerUrlsPaths, PrintWriter writerSecrets, PrintWriter writerSearch) throws ParserConfigurationException {
        this.jadx = jadx;
        this.writerUrlsPaths = writerUrlsPaths;
        this.writerSecrets = writerSecrets;
        this.writerSearch = writerSearch;

        this.factory = DocumentBuilderFactory.newInstance();
        this.factory.setValidating(false);
        this.factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        this.factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        this.factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        this.factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    }

    public void checkConstants(String path, Set<KeyValuePair> keyValuePairs, String searchString) {
        if (keyValuePairs != null) {
            for (KeyValuePair pair : keyValuePairs) {
                String value = pair.getValue();
                if (Helpers.isValidURI(value) && !value.matches(EXCLUDED_LINKS_REGEXP)) {
                    logger.debug("Found URI " + value);
                    urls.add(value);
                }
                if (Helpers.isValidUrlPath(value)) {
                    logger.debug("Found path " + value);
                    paths.add(value);
                }
                if (!urls.contains(value) && !paths.contains(value)) {
                    String secretReason = getSecretReason(pair.getKey(), value);
                    if (secretReason != null) {
                        String key = path + "#" + pair.getKey() + "(" + secretReason + ")";
                        logger.debug("Found secret " + value);
                        if (secrets.containsKey(value)) {
                            secrets.get(value).add(key);
                        } else {
                            secrets.put(value, new HashSet<>(Arrays.asList(key)));
                        }
                    }
                }
                if (searchString != null) {
                    if (value.contains(searchString)) {
                        String key = path + "#" + pair.getKey();
                        logger.debug("Found search string " + value);
                        searchResults.add("* " + key + "\n```\n" + value + "\n```\n");
                    }
                }
            }
        }
    }

    public Set<KeyValuePair> processFile(String name, InputStream is, String searchString) {
        Set<KeyValuePair> keyValuePairs = null;
        switch (Helpers.getFileExtension(name)) {
            case "yaml", "yml" -> {
                try {
                    keyValuePairs = Yml.process(name, is);
                    checkConstants(name, keyValuePairs, searchString);
                } catch (Exception e) {
                    logger.error("Error processing YAML file " + name, e);
                    fallbackParsing(name, is, searchString);
                }
            }
            case "xml" -> {
                try {
                    keyValuePairs = Xml.process(name, is, this.factory);
                    checkConstants(name, keyValuePairs, searchString);
                } catch (Exception e) {
                    logger.error("Error processing XML file " + name, e);
                    fallbackParsing(name, is, searchString);
                }
            }
            case "properties" -> {
                try {
                    keyValuePairs = Properties.process(name, is);
                    checkConstants(name, keyValuePairs, searchString);
                } catch (Exception e) {
                    logger.error("Error processing properties file " + name, e);
                    fallbackParsing(name, is, searchString);
                }
            }
            case "zip", "jar" -> {
                try (ZipFile zip = Helpers.inputSteamToZipFile(is)) {
                    List<ZipEntry> entries = (List<ZipEntry>) Collections.list(zip.entries());

                    entries.parallelStream()
                            .filter(entry -> !entry.isDirectory())
                            .forEach(entry -> {
                                try (InputStream zipEntryIs = zip.getInputStream(entry)) {
                                    processFile(name + "#" + entry.getName(), zipEntryIs, searchString);
                                } catch (IOException ex) {
                                    logger.error("Error processing ZIP entry: {} in {}", entry.getName(), name, ex);
                                }
                            });
                } catch (IOException ex) {
                    logger.error("Error processing file " + name, ex);
                }
            }
            default -> {
                fallbackParsing(name, is, searchString);
            }

        }
        return keyValuePairs;
    }

    public void fallbackParsing(String name, InputStream is, String searchString) {
        try {
            String fileContent = new String(is.readAllBytes());
            extractUrlsAndPaths(fileContent);

            if (searchString != null) {
                Pattern pattern = Pattern.compile(".{0,10}" + Pattern.quote(searchString) + ".{0,10}");
                Matcher matcher = pattern.matcher(fileContent);

                while (matcher.find()) {
                    searchResults.add("* " + name + "\n```\n" + matcher.group() + "\n```\n");
                }
            }
        } catch (IOException ex) {
            logger.error("Error processing file in fallback " + name, ex);
        }
    }

    public void processConstants(String searchString) {
        for (JavaClass cls : jadx.getClasses()) {
            String fullClassName = cls.getFullName();
            Set<KeyValuePair> keyValuePairs = Class.process(fullClassName, cls);
            checkConstants(fullClassName, keyValuePairs, searchString);
        }
        for (ResourceFile resFile : jadx.getResources()) {
            logger.debug("Check constants in " + resFile.getDeobfName());

            AtomicReference<Set<KeyValuePair>> keyValuePairs = new AtomicReference<>();
            ResContainer resContainer = resFile.loadContent();
            ResContainer.DataType dataType = resContainer.getDataType();

            try {
                if (dataType == ResContainer.DataType.RES_LINK) {
                    ResourcesLoader.decodeStream(resContainer.getResLink(), (size, is) -> {
                        keyValuePairs.set(processFile(resFile.getDeobfName(), is, searchString));
                        return null;
                    });
                }

                if (dataType == ResContainer.DataType.TEXT) {
                    InputStream resourceStream = Helpers.getResourceInputStream(resFile, resContainer);
                    if (resourceStream != null) {
                        keyValuePairs.set(processFile(resFile.getDeobfName(), resourceStream, searchString));
                    }
                }

                if (resFile.getType() == ResourceType.ARSC) {
                    keyValuePairs.set(ApkResources.process(resContainer, this.factory));
                }
            } catch (JadxException ex) {
                logger.error("Error processing file " + resFile.getDeobfName(), ex);
            }

            checkConstants(resFile.getDeobfName(), keyValuePairs.get(), searchString);
        }
        writerUrlsPaths.println("**Constants that look like URLs**\r\n");
        urls.stream().sorted().forEach(writerUrlsPaths::println);
        writerUrlsPaths.flush();
        writerUrlsPaths.println("\r\n\r\n**Constants that look like URI paths**\r\n");
        paths.stream().sorted().forEach(writerUrlsPaths::println);
        writerUrlsPaths.flush();
        if (writerSearch != null) {
            writerSearch.println("\r\n\r\n**Search results**\r\n");
            searchResults.stream().sorted().forEach(writerSearch::println);
            writerSearch.flush();
        }
        writerSecrets.println("**Constants that look like secrets**\r\n");
        for (Map.Entry<String, Set<String>> secret : secrets.entrySet()) {
            for (String key : secret.getValue()) {
                writerSecrets.println("* " + key);
            }
            writerSecrets.println("```\n" + secret.getKey() + "\n```");
        }
        writerSecrets.flush();
    }

    private void extractUrlsAndPaths(String content) {
        try {
            Matcher urlMatcher = URL_PATTERN.matcher(content);
            while (urlMatcher.find()) {
                if (!urlMatcher.group().matches(EXCLUDED_LINKS_REGEXP)) {
                    urls.add(urlMatcher.group());
                }
            }
            Matcher quoteMatcher = QUOTE_PATTERN.matcher(content);
            while (quoteMatcher.find()) {
                String potentialPath = quoteMatcher.group(1);
                if (Helpers.isValidUrlPath(potentialPath)) {
                    paths.add(potentialPath);
                }
            }
        } catch (Exception ex) {
            logger.error("Error in extractUrlsAndPaths", ex);
        }
    }

    private double calculateEntropy(String str) {
        int[] charCounts = new int[256];
        for (char c : str.toCharArray()) {
            charCounts[c & 0xFF]++;
        }
        double entropy = 0.0;
        int len = str.length();
        for (int count : charCounts) {
            if (count > 0) {
                double freq = (double) count / len;
                entropy -= freq * (Math.log(freq) / Math.log(2));
            }
        }
        return entropy;
    }

    public boolean isLikelyText(String input) {
        if (input.isEmpty()) {
            return false;
        }
        long spaceCount = input.chars().filter(c -> c == ' ').count();
        long punctuationCount = input.chars().filter(c -> ".!?,。？，".indexOf(c) >= 0).count();
        double spaceRatio = (double) spaceCount / input.length();
        double punctuationRatio = (double) punctuationCount / input.length();
        return (spaceRatio >= 0.06)
                || (spaceRatio >= 0.05 && punctuationRatio >= 0.01 && punctuationRatio <= 0.1);
    }

    private boolean isBase64Like(String str) {
        return str.matches("^[A-Za-z0-9+/=.\r\n]{20,}$") && !str.matches("^(ru|com|org)\\..*") && (str.length() % 4 == 0);
    }

    private boolean isHexLike(String str) {
        return str.matches("^[A-Fa-f0-9-]{16,}$");
    }

    private String getSecretReason(String fieldName, String value) {
        if (!Helpers.isPureAscii(value) || value.matches(EXCLUDED_SECRETS_REGEXP) || value.matches(EXCLUDED_LINKS_REGEXP)) {
            return null;
        }

        String lower = fieldName.toLowerCase();
        for (String secretKeyword : SECRET_KEYWORDS) {
            if (lower.contains(secretKeyword) && calculateEntropy(value) >= ENTROPY_THRESHOLD_MIN && !isLikelyText(value)) {
                return "field name contains " + secretKeyword;
            }
            if (lower.equals(secretKeyword) || lower.endsWith(secretKeyword)) {
                return "field name equal " + secretKeyword;
            }
        }
        if (isHexLike(value)) {
            return "hex string";
        }
        if (isBase64Like(value)) {
            return "base64-like string";
        }

        Matcher matcher = INVALID_CONTROL_CHARS_PATTERN.matcher(value);

        if (calculateEntropy(value) >= ENTROPY_THRESHOLD
                && !isLikelyText(value)
                && !matcher.find()) {
            return "high entropy";
        }
        return null;
    }

}
