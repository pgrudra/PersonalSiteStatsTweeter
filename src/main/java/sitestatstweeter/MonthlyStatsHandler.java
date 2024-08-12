package sitestatstweeter;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.google.gson.Gson;
import feign.Feign;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class MonthlyStatsHandler implements RequestHandler<Object, String> {

    private final String UMAMI_API_KEY = System.getenv("UMAMI_API_KEY");
    private final String UMAMI_API_ENDPOINT = System.getenv("UMAMI_API_CLIENT_ENDPOINT");
    private final String WEBSITE_ID = System.getenv("WEBSITE_ID");
    private final UmamiApi umamiApi;

    private final String TWITTER_CONSUMER_API_KEY = System.getenv("TWITTER_CONSUMER_API_KEY");
    private final String TWITTER_API_CONSUMER_API_KEY_SECRET = System.getenv("TWITTER_API_CONSUMER_API_KEY_SECRET");
    private final String TWITTER_ACCESS_TOKEN = System.getenv("TWITTER_ACCESS_TOKEN");
    private final String TWITTER_ACCESS_TOKEN_SECRET = System.getenv("TWITTER_ACCESS_TOKEN_SECRET");
    private final String TWITTER_API_ENDPOINT = System.getenv("TWITTER_API_ENDPOINT");
    private final TwitterApi twitterApi;

    public MonthlyStatsHandler() {
        // Initialize Feign client for Umami API
        umamiApi = Feign.builder()
                .decoder(new GsonDecoder())
                .target(UmamiApi.class, UMAMI_API_ENDPOINT);
        // Initialize Feign client for Twitter API
        twitterApi = Feign.builder()
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .target(TwitterApi.class, TWITTER_API_ENDPOINT);
    }

    @Override
    public String handleRequest(Object input, Context context) {
        try {
            // Calculate start and end timestamps for the last month
            Instant endAt = Instant.now();
            Instant startAt = endAt.minus(30, ChronoUnit.DAYS);

            // Fetch stats from Umami
            Map<String, Map<String, Integer>> stats = umamiApi.getStats(UMAMI_API_KEY, WEBSITE_ID,
                    startAt.toEpochMilli(),
                    endAt.toEpochMilli());

            // Format tweet
            String tweetContent = formatTweet(stats);
            context.getLogger().log("tweetContent: " + tweetContent);

            // Call Twitter POST API
            Map<String, Object> response = postTweet(tweetContent);
            context.getLogger().log("Twitter API response: " + new Gson().toJson(response));

            return "Tweet posted successfully";
        } catch (Exception e) {
            context.getLogger().log("Error: " + e.getMessage());
            return "Error occurred: " + e.getMessage();
        }
    }

    private String formatTweet(Map<String, Map<String, Integer>> stats) {
        int pageviews = stats.get("pageviews").get("value");
        int visitors = stats.get("visitors").get("value");
        int visits = stats.get("visits").get("value");

        return String.format("Latest monthly stats for my personal website(https://pgrudra.vercel.app):\n" +
                        "📊 Pageviews: %d\n" +
                        "👥 Unique visitors: %d\n" +
                        "🔄 Total visits: %d",
                pageviews, visitors, visits);
    }

    private Map<String, Object> postTweet(String tweetContent) throws Exception {
        String oauthNonce = UUID.randomUUID().toString().replace("-", "");
        String oauthTimestamp = String.valueOf(System.currentTimeMillis() / 1000);

        TreeMap<String, String> parameters = new TreeMap<>();
        parameters.put("oauth_consumer_key", TWITTER_CONSUMER_API_KEY);
        parameters.put("oauth_nonce", oauthNonce);
        parameters.put("oauth_signature_method", "HMAC-SHA1");
        parameters.put("oauth_timestamp", oauthTimestamp);
        parameters.put("oauth_token", TWITTER_ACCESS_TOKEN);
        parameters.put("oauth_version", "1.0");

        String parameterString = createParameterString(parameters);
        String signatureBaseString = "POST&" + urlEncode("https://api.twitter.com/2/tweets") + "&" + urlEncode(parameterString);
        String signingKey = urlEncode(TWITTER_API_CONSUMER_API_KEY_SECRET) + "&" + urlEncode(TWITTER_ACCESS_TOKEN_SECRET);
        String signature = generateSignature(signatureBaseString, signingKey);

        String authorizationHeader = createAuthorizationHeader(parameters, signature);

        return twitterApi.postTweet(authorizationHeader, Map.of("text", tweetContent));
    }

    private String createParameterString(TreeMap<String, String> parameters) {
        StringBuilder parameterString = new StringBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (!parameterString.isEmpty()) {
                parameterString.append("&");
            }
            parameterString.append(urlEncode(entry.getKey())).append("=").append(urlEncode(entry.getValue()));
        }
        return parameterString.toString();
    }

    private String generateSignature(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(rawHmac);
    }

    private String createAuthorizationHeader(TreeMap<String, String> parameters, String signature) {
        StringBuilder header = new StringBuilder("OAuth ");
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            header.append(urlEncode(entry.getKey())).append("=\"").append(urlEncode(entry.getValue())).append("\", ");
        }
        header.append("oauth_signature=\"").append(urlEncode(signature)).append("\"");
        return header.toString();
    }

    private String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.toString())
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex.getCause());
        }
    }


    interface UmamiApi {
        @RequestLine("GET /websites/{websiteId}/stats?startAt={startAt}&endAt={endAt}")
        @Headers("x-umami-api-key: {apiKey}")
        Map<String, Map<String, Integer>> getStats(@Param("apiKey") String apiKey,
                                                   @Param("websiteId") String websiteId,
                                                   @Param("startAt") long startAt,
                                                   @Param("endAt") long endAt);
    }

    interface TwitterApi {
        @RequestLine("POST /2/tweets")
        @Headers({
                "Content-Type: application/json",
                "Authorization: {authHeader}"
        })
        Map<String, Object> postTweet(@Param("authHeader") String authHeader, Map<String, String> tweetContent);
    }
}