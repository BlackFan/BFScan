package ru.blackfan.bfscan.parsing.constants.file;

import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import ru.blackfan.bfscan.helpers.KeyValuePair;

public class Xml {
    private static final Logger logger = LoggerFactory.getLogger(Xml.class);

    public static Set<KeyValuePair> process(String fileName, InputStream xmlContent, DocumentBuilderFactory factory) throws Exception {
        Set<KeyValuePair> keyValuePairs = new HashSet<>();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource inputSource = new InputSource(xmlContent);
            Document document = builder.parse(inputSource);
            processElement(document.getDocumentElement(), keyValuePairs);
        } catch (Exception e) {
            logger.error("Error processing XML file {}: {}", fileName, e.getMessage());
            throw e;
        }
        return keyValuePairs;
    }

    private static void processElement(Element element, Set<KeyValuePair> keyValuePairs) {
        String nodeName = element.getNodeName();
        
        String directText = getDirectTextContent(element).trim();
        if (!directText.isEmpty()) {
            keyValuePairs.add(new KeyValuePair(nodeName, directText));
        }

        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Node attr = attributes.item(i);
            keyValuePairs.add(new KeyValuePair(nodeName + "@" + attr.getNodeName(), attr.getNodeValue()));
        }
        
        if(attributes.getNamedItem("name") != null && attributes.getNamedItem("value") != null) {
            keyValuePairs.add(new KeyValuePair(nodeName + "@" + attributes.getNamedItem("name").getNodeValue(), attributes.getNamedItem("value").getNodeValue()));
        }

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                processElement((Element) child, keyValuePairs);
            }
        }
    }

    private static String getDirectTextContent(Element element) {
        StringBuilder textContent = new StringBuilder();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                textContent.append(child.getNodeValue());
            }
        }
        return textContent.toString();
    }
}
