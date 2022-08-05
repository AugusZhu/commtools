package calc;

import java.math.BigDecimal;

/**
 * @PACKAGE : calc
 * @Author : zhuxianfei
 * @Date : 2022/8/5 23:01
 * @Desc : 金钱格式化工具类
 * @History :
 */
public class MoneyUtils {
    /**
     * <p>将空串或者null值置为0返回。</p>
     * @author sea
     * @param value
     * @return
     */
    public static String getZeroStr(String value) {
        try {
            String temp_n = value;
            if (temp_n == null || temp_n.equals("") || temp_n.equals("null")) {
                temp_n = "0";
            }
            return temp_n;
        } catch (Exception e) {

        }
        return "0";
    }

    /**
     * <p>数字格式化，X,XXX,XXX.XX。</p>
     * @author sea
     * @param numstr
     * @param style
     * @return
     */
    public static  String formatNumberStr(String numstr, String style) {
        try {
            String temp_num = numstr;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }

    /**
     * <p>数字格式化，X,XXX,XXX.XX。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberDouble(double numstr) {
        try {
            String temp_num = String.valueOf(numstr);
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("#,##0.00");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }

    /**
     * <p>数字格式化，X,XXX,XXX.XX。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String getCheckformatNumberDouble(String strnumber,String fieldName,String checkField) {
        try {
            if("all".equals(checkField)||checkField.indexOf(","+fieldName+",")>=0){
                String numstr="";
                if("".equals(strnumber)){
                    numstr="0.00";
                }else{
                    numstr=strnumber;
                }
                String temp_num = String.valueOf(numstr);
                if ((temp_num == null) || (temp_num.equals(""))) {
                    temp_num = "";
                } else {
                    java.text.DecimalFormat ft = new java.text.DecimalFormat("#,##0.00");
                    //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                    BigDecimal bd = new BigDecimal(temp_num);
                    temp_num = ft.format(bd);
                }
                return temp_num;
            }else{
                return strnumber;
            }
        } catch (Exception e) {
        }
        return "";
    }
    /**
     * <p>数字格式化2位，###0.00。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberDoubleTwo(String str) {
        try {
            String temp_num = str;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("###0.00");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    /**
     * <p>数字格式化4位，###0.0000。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberDoubleFour(String str) {
        try {
            String temp_num = str;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("###0.0000");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    /**
     * <p>数字格式化6位，###0.000000。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberDoubleSix(String str) {
        try {
            String temp_num = str;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat( "###0.000000");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    public static  String formatNumberDoubleTwelve(String str) {
        try {
            String temp_num = str;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("###0.000000000000");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    /**
     * <p>数字格式化0位，###0。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberDoubleZero(String str) {
        try {
            String temp_num = str;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("###0");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }

    public static  String formatNumberDoubleZero(double str) {
        try {
            String temp_num = String.valueOf(str);
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat("###0");
                //java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    /**
     *
     * <p>数字格式化，X,XXX,XXX.XX。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberInterest(String numstr)
    {
        try {
            String temp_num = numstr;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat(
                        "#,##0.0000");
                // java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }
    /**
     *
     * <p>数字格式化，X,XXX,XXX.XX。</p>
     * @author sea
     * @param numstr
     * @return
     */
    public static  String formatNumberInterestTwo(String numstr)
    {
        try {
            String temp_num = numstr;
            if ((temp_num == null) || (temp_num.equals(""))) {
                temp_num = "";
            } else {
                java.text.DecimalFormat ft = new java.text.DecimalFormat(
                        "#,##0.00");
                // java.text.DecimalFormat ft =  new java.text.DecimalFormat(style);
                BigDecimal bd = new BigDecimal(temp_num);
                temp_num = ft.format(bd);

            }
            return temp_num;
        } catch (Exception e) {
        }
        return "";
    }

    public static  String formatBooleanStr(String str, int mode) //boolean字符串中文处理,true/flase或1/0转换为是/否,mode=0 0转为是,mode=1 1转为是
    {
        try {
            String temp_bs = str;
            if (mode == 0) {
                if (temp_bs.equals("true") || temp_bs.equals("1")) {
                    temp_bs = "否";
                } else {
                    temp_bs = "是";
                }
            } else {
                if (temp_bs.equals("true") || temp_bs.equals("1")) {
                    temp_bs = "是";
                } else {
                    temp_bs = "否";
                }

            }
            return temp_bs;
        } catch (Exception e) {

        }
        return "";
    }

    public static  String formatBooleanStr(String str) //boolean字符串中文处理的缺省情况,对应于mode=1
    {
        try {
            return formatBooleanStr(str, 1);
        } catch (Exception e) {

        }
        return "";
    }

    public static  double rnddouble(double dbl, int scale) //double四舍五入处理 scale--精度
    {
        try {
            BigDecimal temp_bd = new BigDecimal(dbl);
            double newdbl = temp_bd.setScale(scale, BigDecimal.ROUND_HALF_UP)
                    .doubleValue();
            return newdbl;
        } catch (Exception e) {

        }
        return 0;
    }
}
