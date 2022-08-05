package date;

import lombok.extern.log4j.Log4j;
import org.apache.log4j.Logger;
import org.springframework.util.Assert;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

/**
 * @PACKAGE : date
 * @Author : zhuxianfei
 * @Date : 2022/8/5 23:05
 * @Desc : Date时间处理工具类
 * @History :
 */
@Log4j
public class DateUtils {
    /**
     * log4日志
     */
//    private static Logger log = Logger.getLogger(DateUtils.class);

    /**
     * 默认日期格式
     */
    private static SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd");

    /**
     * 默认日期时间格式
     */
    private static SimpleDateFormat timeFormat = new SimpleDateFormat("yyyyMMddHHmm");

    /**
     * @desc 返回当前日期
     */
    public static Date getCurrentDate() {
        return new Date();

    }

    /**
     * <p>返回当前日期。</p>
     *
     * @param date
     * @return String
     */
    public static String getNullDate(String date) {
        String tempDate = date;
        if (date == null || "".equals(date)) {
            tempDate = getSystemDate(0);
        }
        return tempDate;
    }

    /**
     * <p>转换日期为指定格式的字符串。</p>
     *
     * @param date         日期
     * @param stringformat 字符串格式，表示日期转换成字符串的格式。例如（YYYY-MM-DD,YYYY/MM/DD）
     * @return String
     */
    public static String date2String(Date date, String stringformat) {
        //断言
        Assert.notNull(date);//当 object 不为 null 时抛出异常，notNull(Object object, String message) 方法允许您通过 message 定制异常信息。和 notNull() 方法断言规则相反的方法是 isNull(Object object)/isNull(Object object, String message)，它要求入参一定是 null；
        Assert.hasText(stringformat);//text 不能为 null 且必须至少包含一个非空格的字符，否则抛出异常；
        SimpleDateFormat df = new SimpleDateFormat(stringformat);
        return df.format(date);
    }

    /**
     * <p>格式化字符串日期。</p>
     *
     * @param date String
     * @return String  YYYY-MM-DD
     */
    public static String date2Str(String date) {
        if (date == null) {
            return "";
        }
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            date = sdf.format(sdf.parse(date));
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return date;
    }

    /**
     * <p>转换日期为字符串。</p>
     *
     * @param date
     * @return Object  YYYY-MM-DD HH:mm:ss
     */
    public static String date2String(Date date) {
        if (date == null) {
            return "";
        }
        String format = "yyyy-MM-dd HH:mm:ss";
        return date2String(date, format);
    }

    /**
     * <p>转换日期为字符串，不带时分秒。</p>
     *
     * @param date
     * @return Object
     */
    public static String dateToString(Date date) {
        if (date == null) {
            return "";
        }
        String format = "yyyy-MM-dd";
        return date2String(date, format);
    }

    /**
     * <p>转换字符串类型为日期类型。</p>
     * <pre>格式为yyyyMMdd</pre>
     *
     * @param string 日期字符串
     * @return Date 日期，字符串转换后的日期
     * @throws ParseException
     */
    public static Date toDate(String string) throws ParseException {
        Assert.notNull(string);
        Date cDate = null;
        df.setLenient(true);
        cDate = df.parse(string);
        return cDate;
    }

    /**
     * <p>转换字符串类型为日期时间类型。</p>
     * <pre>格式为yyyyMMddHHmm</pre>
     *
     * @param string 日期时间字符串
     * @return Date 日期，字符串转换后的日期时间
     * @throws ParseException
     */
    public static Date toTime(String string) throws ParseException {
        Assert.notNull(string);
        Date cDate = null;
        timeFormat.setLenient(true);
        cDate = timeFormat.parse(string);
        return cDate;
    }

    /**
     * <p>将日期对象格式化为指定format的日期对象。</p>
     * <pre>如果格式中包含小时、分钟、秒、毫秒，格式后的Date对象中该项值将为0</pre>
     *
     * @param date
     * @param formatString
     * @return Date
     * @throws ParseException
     * @since 1.1
     */
    public static Date format(Date date, String formatString)
            throws ParseException {
        String ds = date2String(date, formatString);
        return toDate(formatString, ds);
    }

    /**
     * <p>获取指定日期当日第一秒的日期。</p>
     * <pre>如:2007-8-11日，返回的为2007-8-11 00:00:00</pre>
     *
     * @param date
     * @return Date
     * @since 1.1
     */
    public static Date getFirstSecondDate(Date date) {
        Date retDate = null;
        try {
            retDate = format(date, "yyyy-MM-dd 00:00:00");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return retDate;
    }

    /**
     * <p>获取指定日期当日最后一秒的日期。</p>
     * <pre>如:2007-8-11日，返回的为2007-8-11 23:59:59</pre>
     *
     * @param date
     * @return Date
     * @since 1.1
     */
    public static Date getLastSecondDate(Date date) {
        Date tmpDate = getFirstSecondDate(date);
        GregorianCalendar cal = new GregorianCalendar();
        cal.setTime(tmpDate);
        cal.add(GregorianCalendar.DATE, 1);
        cal.add(GregorianCalendar.SECOND, -1);
        return cal.getTime();
    }

    /**
     * <p>转换日期字符串为指定格式的日期对象。</p>
     *
     * @param dateFormat 日期的格式字符串
     * @param dateString 日期字符串
     * @return Date 转换后的日期对象
     * @throws ParseException
     */
    public static Date toDate(String dateFormat, String dateString) throws ParseException {
        Assert.notNull(dateFormat);
        Assert.notNull(dateString);
        Date cDate = null;
        SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
        sdf.setLenient(true);
        cDate = sdf.parse(dateString);
        return cDate;
    }

    public static boolean isValidDate(String s) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            sdf.parse(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * <p>判断字符串是否为日期类型。</p>
     *
     * @param dateStr      传入的字符串
     * @param stringformat 日期类型的格式（例如2007/12/12，20071212，2007-12-12）
     * @return Boolean
     */
    public static Boolean isDate(String dateStr, String stringformat) {
        Assert.notNull(dateStr);
        SimpleDateFormat sdf = new SimpleDateFormat(stringformat);
        final String STR = "0123456789/-:";
        if (dateStr.length() != stringformat.length()) {
            return false;
        } else {
            for (int i = 0; i < dateStr.length(); i++) {
                if (STR.indexOf(dateStr.substring(i, i + 1)) == -1) {
                    return false;
                }
            }
            try {
                sdf.setLenient(false);
                sdf.parse(dateStr);
                return true;
            } catch (ParseException e) {
                return false;
            }
        }
    }

    /**
     * <p>参数和现在的系统时间所差的天数。</p>
     *
     * @param date
     * @return 对应的属性值
     */
    public static int gap(Date date) {
        Assert.notNull(date);

        Calendar before = Calendar.getInstance();
        Calendar current = Calendar.getInstance();
        before.setTime(date);
        current.setTime(new Date());
        log.debug(date2String(before.getTime()));
        log.debug(date2String(current.getTime()));
        return (int) ((current.getTimeInMillis() - before.getTimeInMillis()) / (1000 * 60 * 60));
    }

    /**
     * <p>返回两个时间的差数 。</p>
     *
     * @param date1 要比较的时间
     * @param date2 参考时间
     * @return result 相差的小时时间
     */
    public static int getBetweenHours(Date date1, Date date2) {
        if (date1 == null || date2 == null)
            return 0;
        Calendar cal1 = new GregorianCalendar(Locale.CHINA);
        Calendar cal2 = new GregorianCalendar(Locale.CHINA);
        cal1.setTime(date1);
        cal2.setTime(date2);

        long timeMillis1 = cal1.getTimeInMillis();
        long timeMillis2 = cal2.getTimeInMillis();
        long result = (timeMillis2 - timeMillis1) / (1000 * 60 * 60);
        return (int) result;
    }


    /**
     * <p>返回两个时间的差数。</p>
     *
     * @param date1 要比较的时间
     * @param date2 参考时间
     * @return result 相差的小时时间
     */
    public static long getBetweenMins(Date date1, Date date2) {
        if (date1 == null || date2 == null)
            return 0;
        Calendar cal1 = new GregorianCalendar(Locale.CHINA);
        Calendar cal2 = new GregorianCalendar(Locale.CHINA);
        cal1.setTime(date1);
        cal2.setTime(date2);

        long timeMillis1 = cal1.getTimeInMillis();
        long timeMillis2 = cal2.getTimeInMillis();
        long result = (timeMillis2 - timeMillis1) / (1000 * 60);
        return result;
    }

    /**
     * <p>返回与当前时间相差的小时数 。</p>
     *
     * @param date 要比较的时间
     * @return result 相差的小时时间
     */
    public static int getBetweenHours(Date date) {
        Calendar cal1 = new GregorianCalendar(Locale.CHINA);
        Calendar cal2 = new GregorianCalendar(Locale.CHINA);
        cal1.setTime(date);
        cal2.setTime(new Date());

        long timeMillis1 = cal1.getTimeInMillis();
        long timeMillis2 = cal2.getTimeInMillis();
        long result = (timeMillis2 - timeMillis1) / (1000 * 60 * 60);
        return (int) result;
    }

    /**
     * <p>相差的月份间隔。</p>
     *
     * @param bdate
     * @param edate
     * @return 相差的月份间隔
     */
    public static int getBetweenMonths(Date bdate, Date edate) {
        Calendar cal1 = new GregorianCalendar(Locale.CHINA);
        Calendar cal2 = new GregorianCalendar(Locale.CHINA);
        cal1.setTime(bdate);
        cal2.setTime(edate);
        return cal2.get(Calendar.MONTH) - cal1.get(Calendar.MONTH)
                + (cal2.get(Calendar.YEAR) - cal1.get(Calendar.YEAR)) * 12;
    }

    public static int getBetweenMonths(String bdate, String edate, String format) throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        return getBetweenMonths(sdf.parse(bdate), sdf.parse(edate));
    }

    /**
     * <p>返回指定日期前N天的日期。</p>
     *
     * @param cureentDate 当前指定的日期
     * @param n           指定的天数
     * @return Date
     */
    public static Date getBeforeDate(Date cureentDate, int n) {
        Date beforeDate = new Date();
        beforeDate.setTime(cureentDate.getTime() - 24 * 60 * 60 * 1000 * n);
        return beforeDate;
    }

    /**
     * <p>返回指定日期后N天的日期。</p>
     *
     * @param cureentDate 当前指定的日期
     * @param n           指定的天数
     * @return Date
     */
    public static Date getAfterDate(Date cureentDate, int n) {
        Date afterDate = new Date();
        afterDate.setTime(cureentDate.getTime() + 24 * 60 * 60 * 1000 * n);
        return afterDate;
    }

    /**
     * <p>当前日期与该日期之间的天数。</p>
     *
     * @param dateString
     * @return long
     */
    public static long getBetweenDays(String dateString) {
        try {
            java.util.Date dt1 = DateUtils.format(DateUtils.toDate("yyyy-MM-dd", dateString), "yyyy-MM-dd hh:mm:ss");
            java.util.Date dt2 = new java.text.SimpleDateFormat("yyyy-MM-dd hh:mm:ss").parse(DateUtils.date2String(DateUtils.getCurrentDate(), "yyyy-MM-dd hh:mm:ss"));
            Calendar t1 = Calendar.getInstance();
            Calendar t2 = Calendar.getInstance();
            t1.setTime(dt1);
            t2.setTime(dt2);
            long temp = (t2.getTimeInMillis() - t1.getTimeInMillis()) / (1000 * 60 * 60 * 24);
            return temp;
        } catch (ParseException e) {
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * <p>两个日期之间的天数。</p>
     *
     * @param dateString
     * @return long
     */
    public static long getBetweenDays(String startDate, String endDate) {
        try {
            java.util.Date dt1 = DateUtils.format(DateUtils.toDate("yyyy-MM-dd", startDate), "yyyy-MM-dd hh:mm:ss");
            java.util.Date dt2 = DateUtils.format(DateUtils.toDate("yyyy-MM-dd", endDate), "yyyy-MM-dd hh:mm:ss");
            Calendar t1 = Calendar.getInstance();
            Calendar t2 = Calendar.getInstance();
            t1.setTime(dt1);
            t2.setTime(dt2);
            long temp = (t2.getTimeInMillis() - t1.getTimeInMillis()) / (1000 * 60 * 60 * 24);
            return temp;
        } catch (ParseException e) {
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * <p>计算两个日期之间的小时数。</p>
     *
     * @param dateA String
     * @param dateB String
     * @return int
     */
    public static int getBetweenHours(String dateA, String dateB) {
        long dayNumber = 0;
        //1小时=60分钟=3600秒=3600000
        //long mins = 60L * 1000L;
        long hours = 3600000;
        //long day= 24L * 60L * 60L * 1000L;计算天数之差
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        try {
            java.util.Date d1 = df.parse(dateA);
            java.util.Date d2 = df.parse(dateB);
            dayNumber = (d2.getTime() - d1.getTime()) / hours;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return (int) dayNumber;
    }

    /**
     * <p>计算两个日期之间的天数。</p>
     *
     * @param date1
     * @param date2
     * @return long
     */
    public static long DateDays(String date1, String date2) {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        long myTime;
        Date aDate2;
        Date aDate;
        long myTime2;
        long days = 0;
        try {
            aDate = formatter.parse(date1);// 任意日期，包括当前日期
            myTime = (aDate.getTime() / 1000);
            // SimpleDateFormat formatter =new SimpleDateFormat("yyyy-MM-dd");
            aDate2 = formatter.parse(date2);// 任意日期，包括当前日期
            myTime2 = (aDate2.getTime() / 1000);

            if (myTime > myTime2) {
                days = (myTime - myTime2) / (1 * 60 * 60 * 24);
            } else {
                days = (myTime2 - myTime) / (1 * 60 * 60 * 24);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return days;
    }

    /**
     * <p>日期格式化操作，格式化为不带时分秒的格式，如为空则返回空串。</p>
     *
     * @param datestr
     * @return
     */
    public static String getDBDateStr(String datestr) {
        try {
            String temp_date = datestr;
            if ((temp_date == null) || (temp_date.equals(""))
                    || (temp_date.indexOf("1900") >= 0)) {
                temp_date = "";
            } else {
                temp_date = temp_date.substring(0, 10);
            }
            return temp_date;
        } catch (Exception e) {

        }
        return "";
    }


    /**
     * <p>返回系统时间 0--返回时间字符串 1--返回SQL时间字符串。</p>
     *
     * @param rtype 默认：yyyy-MM-dd，2：yyyyMMdd，3：yyyy-MM-dd HH:mm:ss ,4:yyyy/MM/dd HH:mm:ss
     * @return
     */
    public static String getSystemDate(int rtype) {
        try {
            Calendar cal = Calendar.getInstance();
            String module = "yyyy-MM-dd";
            if (rtype == 2) {
                module = "yyyyMMdd";
            }
            if (rtype == 3) {
                module = "yyyy-MM-dd HH:mm:ss";
            }
            if (rtype == 4) {
                module = "yyyy/MM/dd HH:mm:ss";
            }
            SimpleDateFormat formatter1 = new SimpleDateFormat(module);
            String fld_date = formatter1.format(cal.getTime());
            if (rtype == 0)
                return fld_date;
            else if (rtype == 1)
                return "'" + fld_date + "'"; // sql server
            else
                return fld_date;
        } catch (Exception e) {

        }
        return "null";
    }

    /**
     * <p>在原有的日期 对象上添加值可以为年月日时分秒。</p>
     *
     * @param date 所要添加的日期
     * @param leng 所要添加数
     * @param type 添加的类型 :年YEAR/月MONTH/日DAY_OF_YEAR/时HOUR_OF_DAY/分MINUTE
     * @return
     */
    public static Date getDateAdd(Date date, int leng, String type) {
        Date addDate = null;
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        if (type.equals("yy")) {
            cal.add(Calendar.YEAR, leng);
        } else if (type.equals("mm")) {
            cal.add(Calendar.MONTH, leng);
        } else if (type.equals("we")) {
            cal.add(Calendar.WEEK_OF_YEAR, leng);
        } else if (type.equals("dd")) {
            cal.add(Calendar.DAY_OF_YEAR, leng);
        } else if (type.equals("hh")) {
            cal.add(Calendar.HOUR_OF_DAY, leng);
        } else if (type.equals("mi")) {
            cal.add(Calendar.MINUTE, leng);
        } else if (type.equals("ss")) {

        }
        addDate = cal.getTime();
        return addDate;
    }

    /**
     * <p>获得一月中的最后一天。</p>
     *
     * @param year  年
     * @param month 月份
     * @return
     */
    public static String getLastDayOfMonth(String year, String month) {
        Calendar cal = Calendar.getInstance();
        // 年
        cal.set(Calendar.YEAR, Integer.parseInt(year));
        // 月，因为Calendar里的月是从0开始，所以要-1
        cal.set(Calendar.MONTH, Integer.parseInt(month) - 1);
        // 日，设为一号
        cal.set(Calendar.DATE, 1);
        // 月份加一，得到下个月的一号
        cal.add(Calendar.MONTH, 1);
        // 下一个月减一为本月最后一天
        cal.add(Calendar.DATE, -1);
        return String.valueOf(cal.get(Calendar.DAY_OF_MONTH));// 获得月末是几号
    }


    /**
     * <p>返回一个日期的下一年的第一天。</p>
     *
     * @param chargeDate
     * @return
     */
    public static String getYearFirstDay(String chargeDate) {
        Date date;
        String rdate = "";
        try {
            date = toDate(chargeDate);
            rdate = date2String(getDateAdd(date, 1, "yy"), "yyyy-MM-dd");
            rdate = rdate.substring(0, 4) + "-01-01";
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return rdate;

    }

    /**
     * <p>得到下个月的第一天。</p>
     *
     * @param chargeDate
     * @return
     */
    public static String getMonthFirstDay(String chargeDate) {
        Date date;
        String rdate = "";
        try {
            date = toDate(chargeDate);
            rdate = date2String(getDateAdd(date, 1, "mm"), "yyyy-MM-dd");
            rdate = rdate.substring(0, rdate.length() - 2) + "01";
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return rdate;
    }

    /**
     * <p>得到一个日期的年份。</p>
     *
     * @param strDate
     * @return
     */
    public static String getDateYear(String strDate) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Calendar date = Calendar.getInstance();
        date.setTime(sdf.parse(strDate));
        return String.valueOf(date.get(Calendar.YEAR));

    }

    /**
     * <p>得到一个日期的月份。</p>
     *
     * @param strDate
     * @return
     */
    public static String getDateMonth(String strDate) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Calendar date = Calendar.getInstance();
        date.setTime(sdf.parse(strDate));
        return String.valueOf(date.get(Calendar.MONTH) + 1);

    }

    public static Integer getDateDiffMonth(String firstMonth, String secondMonth) throws ParseException {
        Integer f = Integer.parseInt(getDateMonth(firstMonth));
        Integer s = Integer.parseInt(getDateMonth(secondMonth));
        return f - s;
    }

    public static Integer getDateDiffDay(String fD, String sD) throws ParseException {
        Integer f = Integer.parseInt(getDateDay(fD));
        Integer s = Integer.parseInt(getDateDay(sD));
        return f - s;
    }

    public static Integer getDateDiffYear(String fD, String sD) throws ParseException {
        Integer f = Integer.parseInt(getDateYear(fD));
        Integer s = Integer.parseInt(getDateYear(sD));
        return f - s;
    }

    /**
     * <p>得到一个日期的天数。</p>
     *
     * @param strDate
     * @return
     */
    public static String getDateDay(String strDate) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        Calendar date = Calendar.getInstance();
        date.setTime(sdf.parse(strDate));
        return String.valueOf(date.get(Calendar.DAY_OF_MONTH));
    }

    /**
     * <p>比较2个日期大小。</p>
     *
     * @param s1 日期1
     * @param s2 日期2
     * @return s1 > s2 return 1,s1 = s2 return 0,s1 < s2 return -1
     */
    public static int getCompareDate(String s1, String s2) {
        int flag = 0;
        java.text.DateFormat df = new java.text.SimpleDateFormat("yyyy-MM-dd");
        java.util.Calendar c1 = java.util.Calendar.getInstance();
        java.util.Calendar c2 = java.util.Calendar.getInstance();
        try {
            c1.setTime(df.parse(s1));
            c2.setTime(df.parse(s2));
        } catch (java.text.ParseException e) {
            log.info("日期格式不正确");
        }
        int result = c1.compareTo(c2);
        if (result == 0) {
            flag = 0;
            log.info("c1相等c2");
        } else if (result < 0) {
            flag = -1;
            log.info("c1小于c2");
        } else {
            flag = 1;
            log.info("c1大于c2");
        }
        return flag;
    }

    public static int getCompareDate(String s1, String s2, String formatStr) {
        int flag = 0;
        java.text.DateFormat df = new java.text.SimpleDateFormat(formatStr);
        java.util.Calendar c1 = java.util.Calendar.getInstance();
        java.util.Calendar c2 = java.util.Calendar.getInstance();
        try {
            c1.setTime(df.parse(s1));
            c2.setTime(df.parse(s2));
        } catch (java.text.ParseException e) {
            System.err.println("日期格式不正确");
        }
        int result = c1.compareTo(c2);
        if (result == 0) {
            flag = 0;
            System.out.println("c1相等c2");
        } else if (result < 0) {
            flag = -1;
            System.out.println("c1小于c2");
        } else {
            flag = 1;
            System.out.println("c1大于c2");
        }
        return flag;
    }

    /**
     * days360计算天数差
     * 返回两时间间隔天数 bdate--开始时间字符串 edate--结束时间字符串
     *
     * @param strbdate
     * @param stredate
     * @param type     1:欧式算法，0：美式算法
     * @return dateDiff
     */
    public static long days360(String strbdate, String stredate, Integer type) {
        Calendar bdate = Calendar.getInstance();
        Calendar edate = Calendar.getInstance();
        long datediff = 0;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            bdate.setTime(sdf.parse(strbdate));
            edate.setTime(sdf.parse(stredate));
            int monthDiff = getMonthDiff(strbdate, stredate);
            int bday = bdate.get(Calendar.DAY_OF_MONTH);
            int eday = edate.get(Calendar.DAY_OF_MONTH);
            int bmonth = bdate.get(Calendar.MONTH) + 1;
            int byear = bdate.get(Calendar.YEAR);
            int blastday = getLastDayOfMonth(byear, bmonth);
            if (type != null && type == 0) {
                //美国方法：如果起始日期是一个月的最后一天，则将这一天视为同一个月份的第30天；
                //如果终止日期是一个月的第31天、且起始日期早于一个月的第30天，
                //则将这个终止日期视为下一个月的第1天，否则终止日期等于同一个月的第30天。
                if (bday == blastday) {
                    bday = 30;
                }
                if (eday == 31) {
                    if (bday == 30) {
                        eday = 30;
                    } else {
                        eday = 1;
                        monthDiff++;
                    }
                }
            } else {
                //欧洲方法：无论起始日期还是终止日期是一个月的第31天，都视为同一个月份的第30天
                if (bday == 31) {
                    bday = 30;
                }
                if (eday == 31) {
                    eday = 30;
                }
            }
            datediff = eday + (30 - bday) + (monthDiff - 1) * 30;
            return datediff;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return datediff;
    }

    /**
     * 得到两时间的间隔月数
     *
     * @param bdate
     * @param edate
     * @return
     */
    public static int getMonthDiff(String bdate, String edate) {
        try {
            String[] barray = bdate.split("-");
            String[] earray = edate.split("-");
            return (Integer.parseInt(earray[0]) - Integer.parseInt(barray[0])) * 12 + (Integer.parseInt(earray[1]) - Integer.parseInt(barray[1]));
        } catch (Exception e) {

        }
        return 0;
    }

    private static int getLastDayOfMonth(int year, int month) {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month);
        cal.set(Calendar.DAY_OF_MONTH, 1);
        cal.add(Calendar.DAY_OF_MONTH, -1);
        // 某年某月的最后一天
        return cal.get(Calendar.DAY_OF_MONTH);
    }

    public static void main(String[] args) throws Exception {
        String dateStr2 = "2017-02-28";
        String dateStr = "2017-03-28";
        log.info("两个日期之间的天数:"+getBetweenDays(dateStr2, dateStr));
        log.info("美式算法两个日期之间的天数:"+days360(dateStr2, dateStr, 0));
        log.info("欧美式算法两个日期之间的天数:"+days360(dateStr2, dateStr, 1));
    }
}
