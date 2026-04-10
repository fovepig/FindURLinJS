package burp;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class HttpUtil {
    public static String sendPost(String targetUrl, String content) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(targetUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            connection.setDoOutput(true);
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(30000);

            try (OutputStream os = connection.getOutputStream()) {
                os.write(content.getBytes(StandardCharsets.UTF_8));
            }

            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) response.append(line);
                return response.toString();
            }
            return "{\"总数\":\"0\",\"明细\":[]}";
        } catch (Exception e) {
            return "{\"总数\":\"0\",\"明细\":[]}";
        } finally {
            if (connection != null) connection.disconnect();
        }
    }
}
