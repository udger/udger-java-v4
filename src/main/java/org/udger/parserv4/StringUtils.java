/*
  UdgerParser - Java agent string parser based on Udger https://udger.com/products/local_parser

  author     The Udger.com Team (info@udger.com)
  copyright  Copyright (c) Udger s.r.o.
  license    GNU Lesser General Public License
  link       https://udger.com/products
*/
package org.udger.parserv4;

/**
 * The Class StringUtils.
 */
public class StringUtils {

    /**
     * Checks if is not empty.
     *
     * @param s the s
     * @return true, if is not empty
     */
    public static boolean isNotEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    /**
     * Checks if is empty.
     *
     * @param s the s
     * @return true, if is empty
     */
    public static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    /**
     * Trim.
     *
     * @param text the text
     * @param trimBy the trim by
     * @return the string
     */
    public static String trim(String text, String trimBy) {
        if (text != null) {
            int beginIndex = 0;
            int endIndex = text.length();

            while (text.substring(beginIndex, endIndex).startsWith(trimBy)) {
                beginIndex += trimBy.length();
            }

            while (text.substring(beginIndex, endIndex).endsWith(trimBy)) {
                endIndex -= trimBy.length();
            }

            return text.substring(beginIndex, endIndex);
        }
        return null;
    }

    /**
     * Require non null else object.
     *
     * @param value        the value
     * @param defaultValue the default value
     * @return the object
     */
    public static String requireNonNullElse(String value, String defaultValue) {
        return value != null ? value : defaultValue;
    }
}
