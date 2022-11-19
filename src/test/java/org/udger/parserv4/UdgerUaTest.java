package org.udger.parserv4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Paths;
import java.sql.SQLException;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

public class UdgerUaTest {

    public static void main(String args[]) throws Exception {
        InputStream is = UdgerUaTest.class.getResourceAsStream("test_ua.json");
        JsonReader jr = javax.json.Json.createReader(is);
        JsonArray ja = jr.readArray();
        UdgerParser up = null;
        try {
            URL dbResource = UdgerUaTest.class.getResource("udgerdb_v4.dat");
            String dbPath = Paths.get(dbResource.toURI()).toString();
            UdgerParser.ParserDbData parserDbData = new UdgerParser.ParserDbData(dbPath);
            up = new UdgerParser(parserDbData);
            for (int i=0; i < ja.size(); i++) {
                JsonObject jar = ja.getJsonObject(i);
                JsonObject jor = jar.getJsonObject("ret");

                String uaQuery = jar.getJsonObject("test").getString("User-Agent");
                String secChUa = jar.getJsonObject("test").getString("Sec-Ch-Ua");
                String secChUaFullVersionList = jar.getJsonObject("test").getString("Sec-Ch-Ua-Full-Version-List");
                String secChUaMobile = jar.getJsonObject("test").getString("Sec-Ch-Ua-Mobile");
                String secChUaFullVersion = jar.getJsonObject("test").getString("Sec-Ch-Ua-Full-Version");
                String secChUaPlatform = jar.getJsonObject("test").getString("Sec-Ch-Ua-Platform");
                String secChUaPlatformVersion = jar.getJsonObject("test").getString("Sec-Ch-Ua-Platform-Version");
                String secChUaModel = jar.getJsonObject("test").getString("Sec-Ch-Ua-Model");

                UdgerUaRequest.Builder builder = new UdgerUaRequest.Builder();

                if (StringUtils.isNotEmpty(uaQuery)) {
                    builder = builder.withUaString(uaQuery);
                }

                UdgerUaRequest req = builder.withSecChUa(secChUa)
                    .withSecChUaFullVersionList(secChUaFullVersionList)
                    .withSecChUaMobile(secChUaMobile)
                    .withSecChUaFullVersion(secChUaFullVersion)
                    .withSecChUaPlatform(secChUaPlatform)
                    .withSecChUaPlatformVersion(secChUaPlatformVersion)
                    .withSecChUaModel(secChUaModel)
                    .build();

                try {
                    UdgerUaResult ret = up.parseUa(req);
                    System.out.println("### Test : " + (i+1));
                    if (checkResult(ret, jor)) {
                        System.out.println("SUCCEEDED");
                    } else {
                        System.out.println("FAILED!");
                    }
                    System.out.println("Query: " + req.toString());
//                    System.out.println("Result: " + ReflectionToStringBuilder.toString(ret, ToStringStyle.MULTI_LINE_STYLE));
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        } finally {
            if (up != null) {
                try {
                    up.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private static boolean checkResult(UdgerUaResult ret, JsonObject jor) {
        boolean result = true;
        result = testEqual(jor, "ua_engine", ret.getUaEngine()) && result;
        result = testEqual(jor, "ua_version", ret.getUaVersion()) && result;
        result = testEqual(jor, "ua_family_code", ret.getUaFamilyCode()) && result;
        result = testEqual(jor, "ua_family_icon_big", ret.getUaFamilyIconBig()) && result;
        result = testEqual(jor, "crawler_category", ret.getCrawlerCategory()) && result;
        result = testEqual(jor, "ua_family_icon", ret.getUaFamilyIcon()) && result;
        result = testEqual(jor, "ua_family_vendor", ret.getUaFamilyVendor()) && result;
        result = testEqual(jor, "ua_family_vendor_code", ret.getUaFamilyVendorCode()) && result;
        result = testEqual(jor, "ua_uptodate_current_version", ret.getUaUptodateCurrentVersion()) && result;
        result = testEqual(jor, "ua_class_code", ret.getUaClassCode()) && result;
        result = testEqual(jor, "ua", ret.getUa()) && result;
        result = testEqual(jor, "ua_family", ret.getUaFamily()) && result;
        result = testEqual(jor, "ua_family_homepage", ret.getUaFamilyHomepage()) && result;
        result = testEqual(jor, "ua_version_major", ret.getUaVersionMajor()) && result;
        result = testEqual(jor, "ua_family_info_url", ret.getUaFamilyInfoUrl()) && result;
        result = testEqual(jor, "crawler_respect_robotstxt", ret.getCrawlerRespectRobotstxt()) && result;
        result = testEqual(jor, "ua_class", ret.getUaClass()) && result;
        result = testEqual(jor, "ua_family_vendor_homepage", ret.getUaFamilyVendorHomepage()) && result;
        result = testEqual(jor, "crawler_category_code", ret.getCrawlerCategoryCode()) && result;
//        result = testEqual(jor, "ua_string", ret.getUserAgent() != null ? ret.getUserAgent().get) && result;

        result = testEqual(jor, "os_family_vendor_homepage", ret.getOsFamilyVendorHomepage()) && result;
        result = testEqual(jor, "os_icon_big", ret.getOsIconBig()) && result;
        result = testEqual(jor, "os_homepage", ret.getOsHomePage()) && result;
        result = testEqual(jor, "os_icon", ret.getOsIcon()) && result;
        result = testEqual(jor, "os", ret.getOs()) && result;
        result = testEqual(jor, "os_family_code", ret.getOsFamilyCode()) && result;
        result = testEqual(jor, "os_family_vendor", ret.getOsFamilyVendor()) && result;
        result = testEqual(jor, "os_family_vendor_code", ret.getOsFamilyVendorCode()) && result;
        result = testEqual(jor, "os_code", ret.getOsCode()) && result;
        result = testEqual(jor, "os_family", ret.getOsFamily()) && result;
        result = testEqual(jor, "os_info_url", ret.getOsInfoUrl()) && result;

        result = testEqual(jor, "device_class", ret.getDeviceClass()) && result;
        result = testEqual(jor, "device_class_icon_big", ret.getDeviceClassIconBig()) && result;
        result = testEqual(jor, "device_class_icon", ret.getDeviceClassIcon()) && result;
        result = testEqual(jor, "device_class_info_url", ret.getDeviceClassInfoUrl()) && result;
        result = testEqual(jor, "device_class_code", ret.getDeviceClassCode()) && result;

        result = testEqual(jor, "device_marketname", ret.getDeviceMarketname()) && result;
        result = testEqual(jor, "device_brand", ret.getDeviceBrand()) && result;
        result = testEqual(jor, "device_brand_code", ret.getDeviceBrandCode()) && result;
        result = testEqual(jor, "device_brand_homepage", ret.getDeviceBrandHomepage()) && result;
        result = testEqual(jor, "device_brand_icon", ret.getDeviceBrandIcon()) && result;
        result = testEqual(jor, "device_brand_icon_big", ret.getDeviceBrandIconBig()) && result;
        result = testEqual(jor, "device_brand_info_url", ret.getDeviceBrandInfoUrl()) && result;


        result = testEqual(jor, "sec_ch_ua", ret.getSecChUa()) && result;
        result = testEqual(jor, "sec_ch_ua_full_version_list", ret.getSecChUaFullVersionList()) && result;
        result = testEqual(jor, "sec_ch_ua_mobile", ret.getSecChUaMobile()) && result;
        result = testEqual(jor, "sec_ch_ua_full_version", ret.getSecChUaFullVersion()) && result;
        result = testEqual(jor, "sec_ch_ua_platform", ret.getSecChUaPlatform()) && result;
        result = testEqual(jor, "sec_ch_ua_platform_version", ret.getSecChUaPlatformVersion()) && result;
        result = testEqual(jor, "sec_ch_ua_model", ret.getSecChUaModel()) && result;

        return result;
    }

    private static boolean testEqual(JsonObject jor, String test, String ret) {
        String expected = jor.getString(test);
        if (!expected.equals(ret) && expected.startsWith("https://")) {
            expected = expected.replaceAll(" ", "%20");
        }
        if (!expected.equals(ret)) {
            System.out.println("Failed \"" + test + "\" : value=" + ret + "  expected=" + expected);
            return false;
        }
        return true;
    }

}
