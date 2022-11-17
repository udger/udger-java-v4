/*
  UdgerParser - Java agent string parser based on Udger https://udger.com/products/local_parser

  author     The Udger.com Team (info@udger.com)
  copyright  Copyright (c) Udger s.r.o.
  license    GNU Lesser General Public License
  link       https://udger.com/products
*/
package org.udger.parser;

import org.sqlite.SQLiteConfig;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.lang.ref.SoftReference;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main parser's class handles parser requests for user agent or IP.
 */
public class UdgerParser implements Closeable {

    private static final Logger LOG = Logger.getLogger(UdgerParser.class.getName());

    private static final String UDGER_UA_DEV_BRAND_LIST_URL = "https://udger.com/resources/ua-list/devices-brand-detail?brand=";
    private static final String ID_CRAWLER = "crawler";
    private static final Pattern PAT_UNPERLIZE = Pattern.compile("^/?(.*?)/si$");

    /**
     * Holds precalculated data for single DB. Intention is to have single ParserDbData associated with multiple UdgerParser(s)
     */
    public static class ParserDbData {

        private WordDetector clientWordDetector;
        private WordDetector deviceWordDetector;
        private WordDetector osWordDetector;

        private List<IdRegString> clientRegstringList;
        private List<IdRegString> osRegstringList;
        private List<IdRegString> deviceRegstringList;

        private volatile boolean prepared = false;

        private final String dbFileName;

        public ParserDbData(String dbFileName) {
            this.dbFileName = dbFileName;
        }

        protected void prepare(Connection connection) throws SQLException {
            if (!prepared) {
                synchronized (this) {
                    if (!prepared) {
                        clientRegstringList = prepareRegexpStruct(connection, "udger_client_regex");
                        osRegstringList = prepareRegexpStruct(connection, "udger_os_regex");
                        deviceRegstringList = prepareRegexpStruct(connection, "udger_deviceclass_regex");

                        clientWordDetector = createWordDetector(connection, "udger_client_regex", "udger_client_regex_words");
                        deviceWordDetector = createWordDetector(connection, "udger_deviceclass_regex", "udger_deviceclass_regex_words");
                        osWordDetector = createWordDetector(connection, "udger_os_regex", "udger_os_regex_words");
                        prepared = true;
                    }
                }
            }
        }

    }

    private static class ClientInfo {
        private Integer clientId;
        private Integer classId;
    }

    private static class IdRegString {
        int id;
        int wordId1;
        int wordId2;
        Pattern pattern;
    }

    private static class MatcherWithIdRegString {
        private final Matcher matcher;
        private final IdRegString irs;

        private MatcherWithIdRegString(Matcher matcher, IdRegString irs) {
            this.matcher = matcher;
            this.irs = irs;
        }
    }

    private final ParserDbData parserDbData;

    private Connection connection;

    private final Map<String, SoftReference<Pattern>> regexCache = new HashMap<>();

    private final Map<String, PreparedStatement> preparedStmtMap = new HashMap<>();

    private LRUCache<String, UdgerUaResult> cache;

    private boolean osParserEnabled = true;
    private boolean deviceParserEnabled = true;
    private boolean deviceBrandParserEnabled = true;
    private boolean clientHintsParserEnabled = true;
    private boolean inMemoryEnabled = false;

    /**
     * Instantiates a new udger parser with LRU cache with capacity of 10.000 items
     *
     * @param parserDbData the parser data associated with single DB
     */
    public UdgerParser(ParserDbData parserDbData) {
        this(parserDbData, 10000);
    }

    /**
     * Instantiates a new udger parser.
     *
     * @param parserDbData the parser data associated with single DB
     * @param cacheCapacity the LRU cache capacity
     */
    public UdgerParser(ParserDbData parserDbData, int cacheCapacity) {
        this.parserDbData = parserDbData;
        if (cacheCapacity > 0) {
            cache = new LRUCache<>(cacheCapacity);
        }
    }

    /**
     * Instantiates a new udger parser with LRU cache with capacity of 10.000 items
     *
     * @param parserDbData the parser data associated with single DB
     * @param inMemoryEnabled the true for in memory mode
     * @param cacheCapacity the LRU cache capacity
     */
    public UdgerParser(ParserDbData parserDbData, boolean inMemoryEnabled, int cacheCapacity) {
       this(parserDbData, cacheCapacity);
       this.inMemoryEnabled = inMemoryEnabled;
    }

    @Override
    public void close() throws IOException {
        try {
            for (PreparedStatement preparedStmt : preparedStmtMap.values()) {
                preparedStmt.close();
            }
            preparedStmtMap.clear();
            if (connection != null && !connection.isClosed()) {
                connection.close();
                connection = null;
            }
            if (cache != null) {
                cache.clear();
            }
            regexCache.clear();
        } catch (SQLException e) {
            throw new IOException(e.getMessage());
        }
    }

    /**
     * Returns true if the sqlite DB connection has not been closed and is still valid.
     *
     * @param timeoutMillis the timeout millis
     * @return true, if is valid
     * @throws IOException Signals that an I/O exception has occurred.
     */
    public boolean isValid(int timeoutMillis) throws IOException {
        try {
            return connection == null || connection.isValid(timeoutMillis);
        } catch (SQLException e) {
            throw new IOException("Failed to validate connection within " + timeoutMillis + " millis.", e);
        }
    }

    /**
     * Parses the user agent string and stores results of parsing in UdgerUaResult.
     * If the parser was initialized to use an in memory DB, then the DB is not set to read only.
     * This does not matter since the connection is internal to this client, as such there are
     * no chance of external modifications.
     *
     * @param uaString the ua string
     * @return the udger ua result
     * @throws SQLException the SQL exception
     */
    public UdgerUaResult parseUa(String uaString) throws SQLException {
        UdgerUaRequest uaRequest = new UdgerUaRequest.Builder()
                .withUaString(uaString)
                .build();
        uaRequest.setUaString(uaString);
        return parseUa(uaRequest);
    }

    /**
     * Parses the user agent string and stores results of parsing in UdgerUaResult.
     * If the parser was initialized to use an in memory DB, then the DB is not set to read only.
     * This does not matter since the connection is internal to this client, as such there are
     * no chance of external modifications.
     *
     * @param uaRequest the ua request
     * @return the intance of UdgerUaResult storing results of parsing
     * @throws SQLException the SQL exception
     */
    public UdgerUaResult parseUa(UdgerUaRequest uaRequest) throws SQLException {

        UdgerUaResult result;

        if (cache != null) {
            result = cache.get(uaRequest.toString());
            if (result != null) {
                return result;
            }
        }

        prepare();

        result = new UdgerUaResult();

        String uaString = uaRequest.getUaString();

        if (StringUtils.isNotEmpty(uaString)) {
            ClientInfo clientInfo = clientDetector(uaString, result);

            if (!"Crawler".equals(result.getUaClass())) {
                if (osParserEnabled) {
                    osDetector(uaString, result, clientInfo);
                }

                if (deviceParserEnabled) {
                    deviceDetector(uaString, result, clientInfo);
                }

                if (deviceBrandParserEnabled) {
                    if (StringUtils.isNotEmpty(result.getOsFamilyCode())) {
                        fetchDeviceBrand(uaString, result);
                    }
                }
            }
        }

        if (!"Crawler".equals(result.getUaClass())) {
           if (clientHintsParserEnabled) {
               parseClientHints(uaRequest, result);
           }
        }

        if (cache != null) {
            cache.put(uaRequest.toString(), result);
        }

        return result;
    }

    /**
     * Parses the IP string and stores results of parsing in UdgerIpResult.
     *
     * @param ipString the IP string
     * @return the instance of UdgerIpResult storing results of parsing
     * @throws SQLException         the SQL exception
     * @throws UnknownHostException the unknown host exception
     */
    public UdgerIpResult parseIp(String ipString) throws SQLException, UnknownHostException {

        UdgerIpResult result = new UdgerIpResult(ipString);

        InetAddress addr = InetAddress.getByName(ipString);
        Long ipv4int = null;
        String normalizedIp = null;

        if (addr instanceof Inet4Address) {
            ipv4int = 0L;
            for (byte b : addr.getAddress()) {
                ipv4int = ipv4int << 8 | (b & 0xFF);
            }
            normalizedIp = addr.getHostAddress();
        } else if (addr instanceof Inet6Address) {
            normalizedIp = addr.getHostAddress().replaceAll("((?:(?:^|:)0+\\b){2,}):?(?!\\S*\\b\\1:0+\\b)(\\S*)", "::$2");
        }

        result.setIpClassification("Unrecognized");
        result.setIpClassificationCode("unrecognized");

        if (normalizedIp != null) {

            prepare();

            try (ResultSet ipRs = getFirstRow(UdgerSqlQuery.SQL_IP, normalizedIp)) {
                if (ipRs.next()) {
                    fetchUdgerIp(ipRs, result);
                    if (!ID_CRAWLER.equals(result.getIpClassificationCode())) {
                        result.setCrawlerFamilyInfoUrl("");
                    }
                }
            }

            if (ipv4int != null) {
                result.setIpVer(4);
                ResultSet dataCenterRs = getFirstRow(UdgerSqlQuery.SQL_DATACENTER, ipv4int, ipv4int);
                fetchDataCenterAndCloseRs(dataCenterRs, result);
            } else {
                result.setIpVer(6);
                int[] ipArray = ip6ToArray((Inet6Address) addr);
                ResultSet dataCenterRs = getFirstRow(UdgerSqlQuery.SQL_DATACENTER_RANGE6,
                        ipArray[0], ipArray[0],
                        ipArray[1], ipArray[1],
                        ipArray[2], ipArray[2],
                        ipArray[3], ipArray[3],
                        ipArray[4], ipArray[4],
                        ipArray[5], ipArray[5],
                        ipArray[6], ipArray[6],
                        ipArray[7], ipArray[7]
                );
                fetchDataCenterAndCloseRs(dataCenterRs, result);
            }
        }

        return result;
    }

    private void fetchDataCenterAndCloseRs(ResultSet dataCenterRs, UdgerIpResult ret) throws SQLException {
        if (dataCenterRs != null) {
            try {
                if (dataCenterRs.next()) {
                    fetchDataCenter(dataCenterRs, ret);
                }
            } finally {
                dataCenterRs.close();
            }
        }
    }

    /**
     * Checks if is OS parser enabled. OS parser is enabled by default
     *
     * @return true, if is OS parser enabled
     */
    public boolean isOsParserEnabled() {
        return osParserEnabled;
    }

    /**
     * Enable/disable the OS parser. OS parser is enabled by default. If enabled following fields
     * of UdgerUaResult are processed by the OS parser:
     * <ul>
     * <li>osFamily, osFamilyCode, OS, osCode, osHomePage, osIcon, osIconBig</li>
     * <li>osFamilyVendor, osFamilyVendorCode, osFamilyVedorHomepage, osInfoUrl</li>
     * </ul>
     * <p>
     * If the OSs fields are not necessary then disabling this feature can increase
     * the parser's performance.
     *
     * @param osParserEnabled the true if os parser is to be enabled
     */
    public void setOsParserEnabled(boolean osParserEnabled) {
        this.osParserEnabled = osParserEnabled;
    }

    /**
     * Checks if is device parser enabled. Device parser is enabled by default
     *
     * @return true, if device parser is enabled
     */
    public boolean isDeviceParserEnabled() {
        return deviceParserEnabled;
    }

    /**
     * Enable/disable the device parser. Device parser is enabled by default. If enabled following fields
     * of UdgerUaResult are filled by the device parser:
     * <ul>
     * <li>deviceClass, deviceClassCode, deviceClassIcon</li>
     * <li>deviceClassIconBig, deviceClassInfoUrl</li>
     * </ul>
     * <p>
     * If the DEVICEs fields are not necessary then disabling this feature can increase
     * the parser's performance.
     *
     * @param deviceParserEnabled the true if device parser is to be enabled
     */
    public void setDeviceParserEnabled(boolean deviceParserEnabled) {
        this.deviceParserEnabled = deviceParserEnabled;
    }

    /**
     * Checks if is device brand parser enabled. Device brand parser is enabled by default.
     *
     * @return true, if device brand parser is enabled
     */
    public boolean isDeviceBrandParserEnabled() {
        return deviceBrandParserEnabled;
    }

    /**
     * Enable/disable the device brand parser. Device brand parser is enabled by default. If enabled following fields
     * of UdgerUaResult are filled by the device brand parser:
     * <ul>
     * <li>deviceMarketname, deviceBrand, deviceBrandCode, deviceBrandHomepage</li>
     * <li>deviceBrandIcon, deviceBrandIconBig, deviceBrandInfoUrl</li>
     * </ul>
     * <p>
     * If the BRANDs fields are not necessary then disabling this feature can increase
     * the parser's performance.
     *
     * @param deviceBrandParserEnabled the true if device brand parser is to be enabled
     */
    public void setDeviceBrandParserEnabled(boolean deviceBrandParserEnabled) {
        this.deviceBrandParserEnabled = deviceBrandParserEnabled;
    }

    /**
     * Checks if is clients hint parser enabled. Client hint parser is enabled by default.
     *
     * @return true, if device brand parser is enabled
     */
    public boolean isClientHintsParserEnabled() {
        return clientHintsParserEnabled;
    }

    /**
     * Enable/disable the client hint parser. Client hint parser is enabled by default. If enabled following fields
     * of UdgerUaResult are filled by the client hint parser:
     * <ul>
     * <li>secChUa, secChUaFullVersionList, secChUaMobile, secChUaFullVersion</li>
     * <li>secChUaPlatform, secChUaPlatformVersion, deviceBrandInfoUrl</li>
     * </ul>
     * <p>
     * If the client hint fields are not necessary then disabling this feature can increase
     * the parser's performance.
     *
     * @param clientHintsParserEnabled the new client hints parser enabled
     */
    public void setClientHintsParserEnabled(boolean clientHintsParserEnabled) {
        this.clientHintsParserEnabled = clientHintsParserEnabled;
    }

    private static WordDetector createWordDetector(Connection connection, String regexTableName, String wordTableName) throws SQLException {

        Set<Integer> usedWords = new HashSet<>();

        addUsedWords(usedWords, connection, regexTableName, "word_id");
        addUsedWords(usedWords, connection, regexTableName, "word2_id");

        WordDetector result = new WordDetector();

        try (final Statement statement = connection.createStatement();
            final ResultSet rs = statement.executeQuery("SELECT * FROM " + wordTableName)) {
            while (rs.next()) {
                int id = rs.getInt("id");
                if (usedWords.contains(id)) {
                    String word = rs.getString("word").toLowerCase();
                    result.addWord(id, word);
                }
            }
        }
        return result;
    }

    private static void addUsedWords(Set<Integer> usedWords, Connection connection, String regexTableName, String wordIdColumn) throws SQLException {
        try (Statement statement = connection.createStatement();
            ResultSet rs = statement.executeQuery("SELECT " + wordIdColumn + " FROM " + regexTableName)) {
            while (rs.next()) {
                usedWords.add(rs.getInt(wordIdColumn));
            }
        }
    }

    private MatcherWithIdRegString findMatcherIdRegString(String uaString, Set<Integer> foundClientWords, List<IdRegString> list) {
        for (IdRegString irs : list) {
            if ((irs.wordId1 == 0 || foundClientWords.contains(irs.wordId1)) &&
                    (irs.wordId2 == 0 || foundClientWords.contains(irs.wordId2))) {
                Matcher matcher = irs.pattern.matcher(uaString);
                if (matcher.find())
                    return new MatcherWithIdRegString(matcher, irs);
            }
        }
        return null;
    }

    private static List<IdRegString> prepareRegexpStruct(Connection connection, String regexpTableName) throws SQLException {
        List<IdRegString> result = new ArrayList<>();
        try (Statement statement = connection.createStatement();
            ResultSet rs = statement.executeQuery("SELECT rowid, regstring, word_id, word2_id FROM " + regexpTableName + " ORDER BY sequence")) {
            while (rs.next()) {
                IdRegString irs = new IdRegString();
                irs.id = rs.getInt("rowid");
                irs.wordId1 = rs.getInt("word_id");
                irs.wordId2 = rs.getInt("word2_id");
                String regex = rs.getString("regstring");
                Matcher m = PAT_UNPERLIZE.matcher(regex);
                if (m.matches()) {
                    regex = m.group(1);
                }
                irs.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                result.add(irs);
            }
        }
        return result;
    }

    private ClientInfo clientDetector(String uaString, UdgerUaResult result) throws SQLException {
        ClientInfo clientInfo = new ClientInfo();
        try (ResultSet userAgentRs1 = getFirstRow(UdgerSqlQuery.SQL_CRAWLER, uaString)) {
            if (userAgentRs1.next()) {
                fetchUserAgent(userAgentRs1, result);
                clientInfo.classId = 99;
                clientInfo.clientId = -1;
            } else {
                MatcherWithIdRegString mwirs = findMatcherIdRegString(uaString, parserDbData.clientWordDetector.findWords(uaString), parserDbData.clientRegstringList);
                if (mwirs != null) {
                    try (ResultSet userAgentRs2 = getFirstRow(UdgerSqlQuery.SQL_CLIENT, mwirs.irs.id)) {
                        if (userAgentRs2.next()) {
                            fetchUserAgent(userAgentRs2, result);
                            clientInfo.classId = result.getClassId();
                            clientInfo.clientId = result.getClientId();
                            patchVersions(mwirs.matcher, result);
                        }
                    }
                } else {
                    result.setUaClass("Unrecognized");
                    result.setUaClassCode("unrecognized");
                }
            }
        }
        return clientInfo;
    }

    private void osDetector(String uaString, UdgerUaResult result, ClientInfo clientInfo) throws SQLException {
        MatcherWithIdRegString mwirs = findMatcherIdRegString(uaString, parserDbData.osWordDetector.findWords(uaString), parserDbData.osRegstringList);
        if (mwirs != null) {
            try (ResultSet opSysRs = getFirstRow(UdgerSqlQuery.SQL_OS, mwirs.irs.id)) {
                if (opSysRs.next()) {
                    fetchOperatingSystem(opSysRs, result);
                }
            }
        } else {
            if (clientInfo.clientId != null && clientInfo.clientId != 0) {
                try (ResultSet opSysRs = getFirstRow(UdgerSqlQuery.SQL_CLIENT_OS, clientInfo.clientId.toString())) {
                    if (opSysRs.next()) {
                        fetchOperatingSystem(opSysRs, result);
                    }
                }
            }
        }
    }

    private void deviceDetector(String uaString, UdgerUaResult result, ClientInfo clientInfo) throws SQLException {
        MatcherWithIdRegString mwirs = findMatcherIdRegString(uaString, parserDbData.deviceWordDetector.findWords(uaString), parserDbData.deviceRegstringList);
        if (mwirs != null) {
            try (ResultSet devRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE, mwirs.irs.id)) {
                if (devRs.next()) {
                    fetchDevice(devRs, result);
                }
            }
        } else {
            if (clientInfo.classId != null && clientInfo.classId != -1) {
                try (ResultSet devRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_CLASS, clientInfo.classId.toString())) {
                    if (devRs.next()) {
                        fetchDevice(devRs, result);
                    }
                }
            }
        }
    }

    private void fetchDeviceBrand(String uaString, UdgerUaResult result) throws SQLException {
        PreparedStatement preparedStatement = preparedStmtMap.get(UdgerSqlQuery.SQL_DEVICE_REGEX);
        if (preparedStatement == null) {
            preparedStatement = connection.prepareStatement(UdgerSqlQuery.SQL_DEVICE_REGEX);
            preparedStmtMap.put(UdgerSqlQuery.SQL_DEVICE_REGEX, preparedStatement);
        }
        preparedStatement.setObject(1, result.getOsFamilyCode());
        preparedStatement.setObject(2, result.getOsCode());
        try (ResultSet devRegexRs = preparedStatement.executeQuery()) {
            while (devRegexRs.next()) {
                String devId = devRegexRs.getString("id");
                String regex = devRegexRs.getString("regstring");
                if (devId != null && regex != null) {
                    Pattern patRegex = getRegexFromCache(regex);
                    Matcher matcher = patRegex.matcher(uaString);
                    if (matcher.find()) {
                        try (ResultSet devNameListRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_NAME_LIST, devId, matcher.group(1))) {
                            if (devNameListRs.next()) {
                                result.setDeviceMarketname(devNameListRs.getString("marketname"));
                                result.setDeviceBrand(devNameListRs.getString("brand"));
                                result.setDeviceBrandCode(devNameListRs.getString("brand_code"));
                                result.setDeviceBrandHomepage(devNameListRs.getString("brand_url"));
                                result.setDeviceBrandIcon(devNameListRs.getString("icon"));
                                result.setDeviceBrandIconBig(devNameListRs.getString("icon_big"));
                                result.setDeviceBrandInfoUrl(UDGER_UA_DEV_BRAND_LIST_URL + devNameListRs.getString("brand_code"));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }


    private void parseClientHints(UdgerUaRequest uaRequest, UdgerUaResult result) throws SQLException {

        result.setSecChUa(uaRequest.getSecChUa());

        String secChUaFullVersion = StringUtils.trim(uaRequest.getSecChUaFullVersion(), "\"");
        String secChUaFullVersionList = StringUtils.trim(uaRequest.getSecChUaFullVersionList(), "\"");
        String secChUaModel = StringUtils.trim(uaRequest.getSecChUaModel(), "\"");
        String secChUaPlatform = StringUtils.trim(uaRequest.getSecChUaPlatform(), "\"");
        String secChUaPlatformVersion = StringUtils.trim(uaRequest.getSecChUaPlatformVersion(), "\"");

        result.setSecChUaFullVersion(secChUaFullVersion);
        result.setSecChUaFullVersionList(secChUaFullVersionList);
        result.setSecChUaModel(secChUaModel);
        result.setSecChUaPlatform(secChUaPlatform);
        result.setSecChUaPlatformVersion(secChUaPlatformVersion);

        int secChUaMobile = "?0".equals(uaRequest.getSecChUaMobile()) ? 0 : 1;

        result.setSecChUaMobile(String.valueOf(secChUaMobile));

        {
            String regstringSearch1 = secChUaFullVersionList;

            if (StringUtils.isEmpty(regstringSearch1)) {
                regstringSearch1 = uaRequest.getSecChUa();
            }

            if (StringUtils.isNotEmpty(regstringSearch1)) {
                PreparedStatement preparedStatement1 = preparedStmtMap.get(UdgerSqlQuery.SQL_CLIENT_CH_REGEX);
                if (preparedStatement1 == null) {
                    preparedStatement1 = connection.prepareStatement(UdgerSqlQuery.SQL_CLIENT_CH_REGEX);
                    preparedStmtMap.put(UdgerSqlQuery.SQL_CLIENT_CH_REGEX, preparedStatement1);
                }

                preparedStatement1.setObject(1, secChUaMobile);

                try (ResultSet clientChRegexRs = preparedStatement1.executeQuery()) {
                    while (clientChRegexRs.next()) {
                        String regex = clientChRegexRs.getString("regstring");
                        if (regex != null) {
                            Pattern patRegex = getRegexFromCache(regex);
                            Matcher matcher = patRegex.matcher(regstringSearch1);
                            if (matcher.find()) {
                                String ver = matcher.group(1);
                                String verMajor;

                                if (StringUtils.isNotEmpty(secChUaFullVersionList)) {
                                    int dotIndex = ver.indexOf('.');
                                    verMajor = dotIndex >= 0 ? ver.substring(0, dotIndex) : ver;
                                } else {
                                    verMajor = ver;
                                    if (StringUtils.isNotEmpty(secChUaFullVersion)) {
                                        ver = secChUaFullVersion;
                                    }
                                }

                                // $client_id                                        = $r['client_id'];
                                // $client_class_id                                  = $r['class_id'];

                                result.setUaClass(clientChRegexRs.getString("client_classification"));
                                result.setUaClassCode(clientChRegexRs.getString("client_classification_code"));
                                result.setUa(clientChRegexRs.getString("name") + " " + ver);
                                result.setUaVersion(ver);
                                result.setUaVersionMajor(verMajor);
                                result.setUaUptodateCurrentVersion(clientChRegexRs.getString("uptodate_current_version"));
                                result.setUaFamily(clientChRegexRs.getString("name"));
                                result.setUaFamilyCode(clientChRegexRs.getString("name_code"));
                                result.setUaFamilyHomepage(clientChRegexRs.getString("homepage"));
                                result.setUaFamilyVendor(clientChRegexRs.getString("vendor"));
                                result.setUaFamilyVendorCode(clientChRegexRs.getString("vendor_code"));
                                result.setUaFamilyVendorHomepage(clientChRegexRs.getString("vendor_homepage"));
                                result.setUaFamilyIcon(clientChRegexRs.getString("icon"));
                                result.setUaFamilyIconBig(clientChRegexRs.getString("icon_big"));
                                result.setUaFamilyInfoUrl(clientChRegexRs.getString("ua_family_info_url"));
                                result.setUaEngine(clientChRegexRs.getString("engine"));
                                break;
                            }
                        }
                    }
                }
            }
        }

        String regstringSearch2 = secChUaPlatform;
        if (regstringSearch2 != null) {
            // TODO : no checks?
            PreparedStatement preparedStatement2 = preparedStmtMap.get(UdgerSqlQuery.SQL_OS_CH_REGEX);
            if (preparedStatement2 == null) {
                preparedStatement2 = connection.prepareStatement(UdgerSqlQuery.SQL_OS_CH_REGEX);
                preparedStmtMap.put(UdgerSqlQuery.SQL_OS_CH_REGEX, preparedStatement2);
            }

            preparedStatement2.setObject(1, StringUtils.requireNonNullElse(secChUaPlatformVersion, ""));

            try (ResultSet osChRegexRs = preparedStatement2.executeQuery()) {
                while (osChRegexRs.next()) {
                    String regex = osChRegexRs.getString("regstring");
                    if (regex != null) {
                        Pattern patRegex = getRegexFromCache(regex);
                        Matcher matcher = patRegex.matcher(regstringSearch2);
                        if (matcher.find()) {
                            // $os_id                                          = $r['os_id'];
                            result.setOs(osChRegexRs.getString("name"));
                            result.setOsCode(osChRegexRs.getString("name_code"));
                            result.setOsHomePage(osChRegexRs.getString("homepage"));
                            result.setOsIcon(osChRegexRs.getString("icon"));
                            result.setOsIconBig(osChRegexRs.getString("icon_big"));
                            result.setOsInfoUrl(osChRegexRs.getString("os_info_url"));
                            result.setOsFamily(osChRegexRs.getString("family"));
                            result.setOsFamilyCode(osChRegexRs.getString("family_code"));
                            result.setOsFamilyVendor(osChRegexRs.getString("vendor"));
                            result.setOsFamilyVendorCode(osChRegexRs.getString("vendor_code"));
                            result.setOsFamilyVendorHomepage(osChRegexRs.getString("vendor_homepage"));
                            break;
                        }
                    }
                }
            }
        }

        if (StringUtils.isNotEmpty(secChUaModel) && StringUtils.isNotEmpty(result.getOsFamilyCode())) {
            try (ResultSet deviceNameChRegexRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_NAME_CH_REGEX,
                                                             result.getOsFamilyCode(), result.getOsFamilyCode(), result.getOsCode())) {
                if (deviceNameChRegexRs.next()) {
                    try (ResultSet deviceNameChListRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_NAME_LIST_CH,
                                                                    deviceNameChRegexRs.getInt("id"), secChUaModel)) {
                        if (deviceNameChListRs.next()) {
                            result.setDeviceMarketname(deviceNameChListRs.getString("marketname"));
                            result.setDeviceBrand(deviceNameChListRs.getString("brand"));
                            result.setDeviceBrandCode(deviceNameChListRs.getString("brand_code"));
                            result.setDeviceBrandHomepage(deviceNameChListRs.getString("brand_url"));
                            result.setDeviceBrandIcon(deviceNameChListRs.getString("icon"));
                            result.setDeviceBrandIconBig(deviceNameChListRs.getString("icon_big"));
                            result.setDeviceBrandInfoUrl(deviceNameChListRs.getString("brand_info_url"));

                            try (ResultSet deviceClassChRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_CLASS_CH, deviceNameChListRs.getInt("deviceclass_id"))) {
                                if (deviceClassChRs.next()) {
                                  result.setDeviceClass(deviceClassChRs.getString("device_class"));
                                  result.setDeviceClassCode(deviceClassChRs.getString("device_class_code"));
                                  result.setDeviceClassIcon(deviceClassChRs.getString("device_class_icon"));
                                  result.setDeviceClassIconBig(deviceClassChRs.getString("device_class_icon_big"));
                                  result.setDeviceClassInfoUrl(deviceClassChRs.getString("device_class_info_url"));
                                }
                            }
                        }
                    }
                }
            }
        }


        if (StringUtils.isEmpty(result.getDeviceClass()) && StringUtils.isNotEmpty(result.getUaClassCode())) {
            try (ResultSet deviceClassByMobChRs = getFirstRow(UdgerSqlQuery.SQL_DEVICE_CLASS_BY_MOBILE_CH, secChUaMobile)) {
                if (deviceClassByMobChRs.next()) {
                    result.setDeviceClass(deviceClassByMobChRs.getString("device_class"));
                    result.setDeviceClassCode(deviceClassByMobChRs.getString("device_class_code"));
                    result.setDeviceClassIcon(deviceClassByMobChRs.getString("device_class_icon"));
                    result.setDeviceClassIconBig(deviceClassByMobChRs.getString("device_class_icon_big"));
                    result.setDeviceClassInfoUrl(deviceClassByMobChRs.getString("device_class_info_url"));
                }
            }
        }
    }


    private int[] ip6ToArray(Inet6Address addr) {
        int[] ret = new int[8];
        byte[] bytes = addr.getAddress();
        for (int i = 0; i < 8; i++) {
            ret[i] = ((bytes[i * 2] << 8) & 0xff00) | (bytes[i * 2 + 1] & 0xff);
        }
        return ret;
    }

    private void prepare() throws SQLException {
        connect();
        parserDbData.prepare(connection);
    }

    private void connect() throws SQLException {
        if (connection == null) {
            SQLiteConfig config = new SQLiteConfig();
            config.setReadOnly(true);
            if (inMemoryEnabled) {
                // we cannot use read only for in memory DB since we need to populate this DB from the file.
                connection = DriverManager.getConnection("jdbc:sqlite::memory:");
                File dbfile = new File(parserDbData.dbFileName);
                try (Statement statement = connection.createStatement()) {
                    statement.executeUpdate("restore from " + dbfile.getPath());
                } catch (Exception e) {
                    LOG.warning("Error re-constructing in memory data base from Db file " + dbfile);
                }
            } else {
                connection = DriverManager.getConnection("jdbc:sqlite:" + parserDbData.dbFileName, config.toProperties());
            }
        }
    }

    private Pattern getRegexFromCache(String regex) {
        SoftReference<Pattern> patRegex = regexCache.get(regex);
        if (patRegex == null || patRegex.get() == null) {
            Matcher m = PAT_UNPERLIZE.matcher(regex);
            if (m.matches()) {
                regex = m.group(1);
            }
            patRegex = new SoftReference<>(Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
            regexCache.put(regex, patRegex);
        }
        return patRegex.get();
    }

    private ResultSet getFirstRow(String query, Object... params) throws SQLException {
        PreparedStatement preparedStatement = preparedStmtMap.get(query);
        if (preparedStatement == null) {
            preparedStatement = connection.prepareStatement(query);
            preparedStmtMap.put(query, preparedStatement);
        }
        for (int i = 0; i < params.length; i++) {
            preparedStatement.setObject(i + 1, params[i]);
        }
        preparedStatement.setMaxRows(1);
        return preparedStatement.executeQuery();
    }


    private void fetchUserAgent(ResultSet rs, UdgerUaResult ret) throws SQLException {
        ret.setClassId(rs.getInt("class_id"));
        ret.setClientId(rs.getInt("client_id"));
        ret.setCrawlerCategory(nvl(rs.getString("crawler_category")));
        ret.setCrawlerCategoryCode(nvl(rs.getString("crawler_category_code")));
        ret.setCrawlerLastSeen(nvl(rs.getString("crawler_last_seen")));
        ret.setCrawlerRespectRobotstxt(nvl(rs.getString("crawler_respect_robotstxt")));
        ret.setUa(nvl(rs.getString("ua")));
        ret.setUaClass(nvl(rs.getString("ua_class")));
        ret.setUaClassCode(nvl(rs.getString("ua_class_code")));
        ret.setUaEngine(nvl(rs.getString("ua_engine")));
        ret.setUaFamily(nvl(rs.getString("ua_family")));
        ret.setUaFamilyCode(nvl(rs.getString("ua_family_code")));
        ret.setUaFamilyHomepage(nvl(rs.getString("ua_family_homepage")));
        ret.setUaFamilyIcon(nvl(rs.getString("ua_family_icon")));
        ret.setUaFamilyIconBig(nvl(rs.getString("ua_family_icon_big")));
        ret.setUaFamilyInfoUrl(nvl(rs.getString("ua_family_info_url")));
        ret.setUaFamilyVendor(nvl(rs.getString("ua_family_vendor")));
        ret.setUaFamilyVendorCode(nvl(rs.getString("ua_family_vendor_code")));
        ret.setUaFamilyVendorHomepage(nvl(rs.getString("ua_family_vendor_homepage")));
        ret.setUaUptodateCurrentVersion(nvl(rs.getString("ua_uptodate_current_version")));
        ret.setUaVersion(nvl(rs.getString("ua_version")));
        ret.setUaVersionMajor(nvl(rs.getString("ua_version_major")));
    }

    private void fetchOperatingSystem(ResultSet rs, UdgerUaResult ret) throws SQLException {
        ret.setOsFamily(nvl(rs.getString("os_family")));
        ret.setOs(nvl(rs.getString("os")));
        ret.setOsCode(nvl(rs.getString("os_code")));
        ret.setOsFamilyCode(nvl(rs.getString("os_family_code")));
        ret.setOsFamilyVendorHomepage(nvl(rs.getString("os_family_vendor_homepage")));
        ret.setOsFamilyVendor(nvl(rs.getString("os_family_vendor")));
        ret.setOsFamilyVendorCode(nvl(rs.getString("os_family_vendor_code")));
        ret.setOsHomePage(nvl(rs.getString("os_home_page")));
        ret.setOsIcon(nvl(rs.getString("os_icon")));
        ret.setOsIconBig(nvl(rs.getString("os_icon_big")));
        ret.setOsInfoUrl(nvl(rs.getString("os_info_url")));
    }

    private void fetchDevice(ResultSet rs, UdgerUaResult ret) throws SQLException {
        ret.setDeviceClass(nvl(rs.getString("device_class")));
        ret.setDeviceClassCode(nvl(rs.getString("device_class_code")));
        ret.setDeviceClassIcon(nvl(rs.getString("device_class_icon")));
        ret.setDeviceClassIconBig(nvl(rs.getString("device_class_icon_big")));
        ret.setDeviceClassInfoUrl(nvl(rs.getString("device_class_info_url")));
    }

    private void patchVersions(Matcher lastPatternMatcher, UdgerUaResult ret) {
        if (lastPatternMatcher != null) {
            String version = "";
            if (lastPatternMatcher.groupCount() >= 1) {
                version = lastPatternMatcher.group(1);
                if (version == null) {
                    version = "";
                }
            }
            ret.setUaVersion(version);
            String[] versionSegments = version.split("\\.");
            if (versionSegments.length > 0) {
                ret.setUaVersionMajor(version.split("\\.")[0]);
            } else {
                ret.setUaVersionMajor("");
            }
            ret.setUa((ret.getUa() != null ? ret.getUa() : "") + " " + version);
        } else {
            ret.setUaVersion("");
            ret.setUaVersionMajor("");
        }
    }

    private void fetchUdgerIp(ResultSet rs, UdgerIpResult result) throws SQLException {
        result.setCrawlerCategory(nvl(rs.getString("crawler_category")));
        result.setCrawlerCategoryCode(nvl(rs.getString("crawler_category_code")));
        result.setCrawlerFamily(nvl(rs.getString("crawler_family")));
        result.setCrawlerFamilyCode(nvl(rs.getString("crawler_family_code")));
        result.setCrawlerFamilyHomepage(nvl(rs.getString("crawler_family_homepage")));
        result.setCrawlerFamilyIcon(nvl(rs.getString("crawler_family_icon")));
        result.setCrawlerFamilyInfoUrl(nvl(rs.getString("crawler_family_info_url")));
        result.setCrawlerFamilyVendor(nvl(rs.getString("crawler_family_vendor")));
        result.setCrawlerFamilyVendorCode(nvl(rs.getString("crawler_family_vendor_code")));
        result.setCrawlerFamilyVendorHomepage(nvl(rs.getString("crawler_family_vendor_homepage")));
        result.setCrawlerLastSeen(nvl(rs.getString("crawler_last_seen")));
        result.setCrawlerName(nvl(rs.getString("crawler_name")));
        result.setCrawlerRespectRobotstxt(nvl(rs.getString("crawler_respect_robotstxt")));
        result.setCrawlerVer(nvl(rs.getString("crawler_ver")));
        result.setCrawlerVerMajor(nvl(rs.getString("crawler_ver_major")));
        result.setIpCity(nvl(rs.getString("ip_city")));
        result.setIpClassification(nvl(rs.getString("ip_classification")));
        result.setIpClassificationCode(nvl(rs.getString("ip_classification_code")));
        result.setIpCountry(nvl(rs.getString("ip_country")));
        result.setIpCountryCode(nvl(rs.getString("ip_country_code")));
        result.setIpHostname(nvl(rs.getString("ip_hostname")));
        result.setIpLastSeen(nvl(rs.getString("ip_last_seen")));
    }

    private String nvl(String v) {
        return v != null ? v : "";
    }

    private void fetchDataCenter(ResultSet rs, UdgerIpResult result) throws SQLException {
        result.setDataCenterHomePage(nvl(rs.getString("datacenter_homepage")));
        result.setDataCenterName(nvl(rs.getString("datacenter_name")));
        result.setDataCenterNameCode(nvl(rs.getString("datacenter_name_code")));
    }

}
