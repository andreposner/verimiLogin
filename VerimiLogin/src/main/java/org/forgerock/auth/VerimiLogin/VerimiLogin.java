/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.auth.VerimiLogin;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContexts;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.oauth2.core.OAuth2Jwt;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.Socket;
import java.net.URLEncoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.TimeUnit;

// import org.forgerock.json.jose.jwt.JwtClaimsSet;

// import java.security.Key;

// import com.nimbusds.jose..;
// import com.nimbusds.jose.jwk.source.*;
// import com.nimbusds.jwt.*;
// import com.nimbusds.jwt.proc.*;

// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import io.jsonwebtoken.security.Keys;


// import sun.util.resources.LocaleData;
// import javax.json.Json;
// import javax.json.JsonArray;
// import javax.json.JsonObject;
// import javax.json.JsonReader;
//import javax.json.JsonValue;
// import sun.security.ssl.Debug;

/**
 * A node that uses Verimi for external AuthN
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = VerimiLogin.Config.class)
public class VerimiLogin extends AbstractDecisionNode {

    private final static String AUTHORIZATION_CODE = "authorization_code";
    private final static String CODE = "code";
    private final static String DEBUG_FILE = "VerimiLogin";

    private final Logger logger = LoggerFactory.getLogger(VerimiLogin.class);

    private final Config config;
    private final String realm;

    private String apiUri;
    private String redirectUrl;
    private String issuer;
    private Boolean require2FA;
    private String client_id;
    private String client_secret;
    private String trustStoreFile;
    private String trustStorePassword;
    private String keyStoreFile;
    private String keyStorePassword;
    private String timeout;
    private String connectionTimeout;

    private String authCode;
    private String verimiId;
    private String verimiEmail;
    private String verimiName;
    private String verimiAddress;

    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String wellknownEndpoint() {
            return "https://api.uat.verimi.cloud/.well-known/openid-configuration";
        }

        @Attribute(order = 200)
        default String apiUri() {
            return "https://api.uat.verimi.cloud/dipp/api";
        }

        @Attribute(order=300)
            default String redirectUrl() {
            return "";
        }

        @Attribute(order = 400)
        default String client_id() {
            return "";
        }

        @Attribute(order = 500)
        default String client_secret() {
            return "";
        }

        @Attribute(order=600)
        default String scopes() {
            // return "";
            return "name email address";
        }

        // find useful defaults
        @Attribute(order=700)
        default String issuer(){
            return "https://web.uat.verimi.cloud/";
        }

        @Attribute(order = 800)
        default Boolean require2FA() {
            return false;
        }

        @Attribute(order = 900)
        default String trustStoreFile() {
            return "";
        }

        @Attribute(order = 1000)
        default String trustStorePassword() {
            return "";
        }

        @Attribute(order = 1100)
        default String keyStoreFile() {
            return "";
        }

        @Attribute(order = 1200)
        default String keyStorePassword() {
            return "";
        }

        @Attribute(order = 1300)
        default String timeout() {
            return"80";
        }

        @Attribute(order = 1400)
        default Integer connectionTimeout() {
            return 90;
        }

        @Attribute(order = 1500)
        default String pseudonymSharedStateVar() {
            return "verimiId";
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public VerimiLogin(@Assisted Config config, @Assisted Realm realm ) {
        this.config = config;
        this.realm = realm.toString();
    }

    public void debugmessage(String s){
        System.out.println(s);
    }

    private String encodeUrl (String url) {
        try {
            return URLEncoder.encode(url, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    private String extractCode (String requestParameters) {
        String code="";
        String[] attrValuePair = requestParameters.split(",", 0);
        // int nu = attrValuePair.length;
        for (int i=0; i<attrValuePair.length ; i++) {
            String aP = attrValuePair[i].trim();
            // debugmessage("[" + DEBUG_FILE + "]: Found attr value pair: '" + aP + "'.");
            if (aP.startsWith("code")) {
                String[] tc = aP.split("=", 0);
                code = tc[1].substring(1,tc[1].length()-1);
            }
        }
        debugmessage("[" + DEBUG_FILE + "]: Found auth code: '" + code + "' in request.");
        return code;
    }

    public SSLContext initSSLContext() {
       try {
           final KeyStore keyStore = KeyStore.getInstance("PKCS12");
           keyStore.load(new FileInputStream(config.keyStoreFile()), config.keyStorePassword().toCharArray());
           final KeyStore trustStore = KeyStore.getInstance("PKCS12");
           trustStore.load(new FileInputStream(config.trustStoreFile()), config.trustStorePassword().toCharArray());

           Enumeration<String>  aliases = keyStore.aliases();
           StringBuilder output = new StringBuilder();
           while (aliases.hasMoreElements()) {
               output.append(aliases.nextElement());
           }
           String finalOutput = output.toString();

           final SSLContext sslContext = SSLContexts.custom()
                   .loadTrustMaterial(trustStore, null)
                   .loadKeyMaterial(keyStore, config.keyStorePassword().toCharArray(), new PrivateKeyStrategy() {
                       @Override
                       public String chooseAlias(Map<String, PrivateKeyDetails> map, Socket socket) {
                           debugmessage("[" + DEBUG_FILE + "]: private key alias: '" + finalOutput + "'.");
                           return finalOutput;
                       }
                   })
                   .build();
           return sslContext;
       } catch (KeyStoreException | UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException
               | IOException | KeyManagementException e)
           {
           e.printStackTrace();
        }
       return null;
    }

    // private boolean validateVerimiResponse (OAuth2Jwt jwt) throws InvalidGrantException {
    private boolean validateVerimiResponse (StringBuilder jwtwjws) {
        String accessToken = jwtwjws.toString();

        try {
            ObjectMapper resOM = new ObjectMapper();
            JsonNode resRootNode = resOM.readTree(accessToken);
            JsonNode idTokenWithJOSEandJWS = resRootNode.path("id_token");
            String idString = idTokenWithJOSEandJWS.asText();
            debugmessage("[" + DEBUG_FILE + "]: Found ID token (with JOSE header and signature): '" + idString + "'; split it ...");

            OAuth2Jwt jwt = OAuth2Jwt.create(idString);

            // Checks required by https://tools.ietf.org/html/rfc7523#section-3
            // 1. MUST contain an issuer claim
            String issuer = jwt.getIssuer();
            if (Strings.isBlank(issuer)) {
                // throw new InvalidGrantException("Missing 'iss' claim in JWT assertion");
                debugmessage("[" + DEBUG_FILE + "]: Missing 'iss' claim in JWT assertion");
            } else {
                if (!jwt.getIssuer().equals(config.issuer())) {
                    // throw new InvalidGrantException("'iss' claim: '" + jwt.getIssuer() + "' does not match configured issuer: '" + config.issuer() + "'.");
                    debugmessage("[" + DEBUG_FILE + "]: Issuer from 'iss' claim: '" + jwt.getIssuer() + "' does not match configured issuer: '" + config.issuer() + "'.");
                    return false;
                }
            }
            // 2. MUST contain a subject claim
            String subject = jwt.getSubject();
            if (Strings.isBlank(subject)) {
                // throw new InvalidGrantException("Missing 'sub' claim in JWT assertion");
                debugmessage("[" + DEBUG_FILE + "]: Missing 'sub' claim in JWT assertion");
                return false;
            } else {
                verimiId = subject;
            }
            // 3. MUST contain an audience claim, matching one of the valid values for this tree in this tree in this realm
            if (!jwt.isIntendedForAudience(config.client_id())) {
                // throw new InvalidGrantException("incorrect audience in JWT");
                debugmessage("[" + DEBUG_FILE + "]: Audience claim 'aud' does not contain configured audience: '" + config.client_id() + "'.");
                return false;
            }
            // 4-6. Check exp, iat, nbf claims
            if (!jwt.isContentValid()) {
                // throw new InvalidGrantException("JWT assertion is expired or invalid");
                debugmessage("[" + DEBUG_FILE + "]: JWT assertion is expired or invalid");
                return false;
            }
            // Check the algorithm is sensible
            JwsAlgorithm algorithm = jwt.getSignedJwt().getHeader().getAlgorithm();
            switch (algorithm.getAlgorithmType()) {
                case RSA:
                case ECDSA:
                case EDDSA:
                    // Public key algorithms are ok
                    break;
                default:
                    // NONE and HMAC:
                    // throw new InvalidGrantException("Unsupported signature algorithm " + algorithm + ": only public key " +
                    debugmessage("[" + DEBUG_FILE + "]: Unsupported signature algorithm " + algorithm + ": only public key signatures supported.");
                    return false;
            }

            // TODO: check signature

            // TODO make it generic
            verimiEmail = jwt.getSignedJwt().getClaimsSet().getClaim("email", String.class);
            verimiName = jwt.getSignedJwt().getClaimsSet().getClaim("name", String.class);
            verimiAddress = jwt.getSignedJwt().getClaimsSet().getClaim("address", String.class);

            return true;
        } catch (IOException e) {
            debugmessage("[" + DEBUG_FILE + "]: Could not extact ID token from Verimi response: \n" + e.toString());
            e.printStackTrace();
        }
        return false;
    }

    private Boolean AuthZRequest(String authCode) {
        StringBuilder response = new StringBuilder();

        String authzUri = config.apiUri() + "/oauth2/token?grant_type=authorization_code&code=" + authCode + "&redirect_uri=" + encodeUrl(config.redirectUrl());
        String authHeader = Base64.getEncoder().encodeToString((config.client_id()+":"+config.client_secret()).getBytes());
        try {
            // initalize
            final SSLContext sslContext = initSSLContext();
            HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).setConnectionTimeToLive(config.connectionTimeout(), TimeUnit.SECONDS).build();

            // POST
            HttpPost jsonRequest = new HttpPost(authzUri);
            jsonRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");
            jsonRequest.setHeader("Authorization", "Basic " + authHeader);
            String payload = "";
            StringEntity entity = new StringEntity(payload);
            jsonRequest.setEntity(entity);
            HttpResponse jsonResponse = httpClient.execute(jsonRequest);

            // Display request URI
            debugmessage("[" + DEBUG_FILE + "]: Request URI: '" + authzUri + "'.");

            //Display request Headers
            List<Header> httpHeaders = Arrays.asList(jsonRequest.getAllHeaders());
            for (Header header : httpHeaders) {
                debugmessage("[" + DEBUG_FILE + "]: Request header: 'name','value': '" + header.getName() + "', '" + header.getValue() + "'.");
            }

            // Display response body
            BufferedReader res = new BufferedReader(new InputStreamReader(jsonResponse.getEntity().getContent()));
            String outputRes;
            while ((outputRes = res.readLine()) != null) {
                response.append(outputRes);
            }
            debugmessage("[" + DEBUG_FILE + "]: Response: '" + response.toString() + "'.");

            // OAuth2Jwt jwtResponse = OAuth2Jwt.create(response.toString());

            // e.g.
            // [VerimiLogin]: Response:
            // '{
            //   "access_token":"xpejKY1SeWs8yVoPjReiQAohqYtT1Tx-OKQ_ffUTo8E.J3VYOFrjyeppofTlST3e_EG16OIoer19mfOfgoGZ6sI",
            //   "expires_in":1800,
            //   "token_type":"bearer",
            //   "scope":"openid login",
            //   "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzo3NGFmZmRmYS0xOTVjLTRiZTAtOGNlZi04ZjQ5OWI2ZTViNDciLCJ0eXAiOiJKV1QifQ.eyJhY3IiOiJsb2EuZGlwcC5kZWZhdWx0IiwiYXRfaGFzaCI6IjJZYXdiSjFhT2o3T05DNjBxVzh3MVEiLCJhdWQiOlsiZm9yZ2Vyb2NrIl0sImF1dGhfdGltZSI6MTU3MjMzNTc0NCwiZXhwIjoxNTcyMzM3NjEwLCJpYXQiOjE1NzIzMzU4MTAsImlzcyI6Imh0dHBzOi8vd2ViLnVhdC52ZXJpbWkuY2xvdWQvIiwianRpIjoiY2Q1YTFmZDAtZmI3MS00NTNhLTliN2YtZGY2NWI1NDYwYWM0Iiwibm9uY2UiOiIiLCJyYXQiOjE1NzIzMzU3MzcsInN1YiI6IjA5ZmYzZmZmLTkzM2UtNDllZC04Mzk0LTZlZDgzZWI0NDY4ZSJ9.I3nHm2Ne1lust2ygJgW3Eanodo4MjdkqS3VUinWjn0L7YakyikSwXI2SN10YnZX6mAXP8UD4FMhUIbm-00nlfvuMZw395ttmUD1SoVqZf1G-3Xpu0esYXmGYNwHDih3oHG0LrNBuHAs5t3m62n0b9AfxYNXqrp90d5HaFs-gCYNpcCULLVTr3SPJISUZTLAgM_ur5tJRG_yk2G42vrL4PIVZH37z2E1Ign64sS76Olu6KGJHO2akRaNrQIP7Pi7FtIUcSB347svOd-8btJtbppjqtOfS9-1lWJYu0mi4xTGGU4XTa2HQ9fPD_n_DJIFz3ZiIKwclmzsCFPs1_yauXg"
            //   }'.

            // Display Status Code
            int statusCode = jsonResponse.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                debugmessage("[" + DEBUG_FILE + "]: HTTP result code was 200/OK; will now validate response ...");
                if (validateVerimiResponse(response)){
                    debugmessage("[" + DEBUG_FILE + "]: Validation of response was successful, found Verimi ID: '" + verimiId + "'.");
                    return true;
                }
            } else {
                debugmessage("[" + DEBUG_FILE + "]: HTTP result code: '" +  statusCode + "' != 200/OK => access denied.");
                return false;
            }
        }  catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        debugmessage("[" + DEBUG_FILE + "]: VerimiLogin started, reading configuration ...");
        debugmessage("[" + DEBUG_FILE + "]: Verimi API URI: '" + config.apiUri() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Redirect URL: '" + config.redirectUrl() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: client_id: '" + config.client_id() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: client_secret: '" + config.client_secret() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Truststore file: '" + config.trustStoreFile() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Truststore password: '" + config.trustStorePassword()+ "'.");
        debugmessage("[" + DEBUG_FILE + "]: Keystore file: '" + config.keyStoreFile() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Keystore password: '" + config.keyStorePassword() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: Timeout: '" + config.timeout() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: connection timeout: '" + config.connectionTimeout() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: VerimiIdAttribute: '" + config.pseudonymSharedStateVar() + "'.");
        debugmessage("[" + DEBUG_FILE + "]: End reading configuration.");
        debugmessage("[" + DEBUG_FILE + "]: ============================================");

        // Request parameters  : {authIndexValue=[VerimiTree], authIndexType=[service], realm=[/], verimiAuthCode=[blub], locale=[de]}
        String reqParams = context.request.parameters.toString().substring(1, context.request.parameters.toString().length()-1);
        debugmessage("[" + DEBUG_FILE + "]: Found query string: '" + reqParams.trim() + "' in request; will extract auth code ...");

        String authCode = extractCode(reqParams);
        if (AuthZRequest(authCode) == true) {
            debugmessage("[" + DEBUG_FILE + "]: Write Verimi ID: '" + verimiId + "' to shared state attribute: '" + config.pseudonymSharedStateVar() + "'.");
            context.sharedState.put(config.pseudonymSharedStateVar(), verimiId);
            context.sharedState.put("verimiEmail", verimiEmail);
            context.sharedState.put("verimiName", verimiName);
            context.sharedState.put("verimiAddress", verimiAddress);
            return goTo(true).build();
        } else {
            debugmessage("[" + DEBUG_FILE + "]: Verimi authorization failed!");
            return goTo(false).build();
        }

        // return goTo(true).build();
    }
}
