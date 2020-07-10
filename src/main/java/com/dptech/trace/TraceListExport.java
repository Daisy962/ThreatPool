package com.dptech.trace;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.ConcurrentHashMultiset;
import com.google.common.collect.Lists;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.kafka.common.protocol.types.Field;

import static com.dptech.trace.utils.HttpRequestUtil.postRequest;


public class TraceListExport {
    private static boolean outputFlag = true;
    private static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static String esHttpStr = "http://%s:9200/%s/_search?pretty=true";
    private static String indexStr = "threat_index_%s";
    private static String esBody = "{\n" +
            "  \"size\": 10000,\n" +
            "  \"query\": {\n" +
            "    \"bool\": {\n" +
            "      \"filter\": [\n" +
            "        {\n" +
            "          \"range\": {\n" +
            "            \"timestamp\": {\n" +
            "              \"gte\": %s,\n" +
            "              \"lte\": %s\n" +
            "            }\n" +
            "          }\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  },\n" +
            "  \"sort\": [\n" +
            "    {\n" +
            "      \"uid\": {\n" +
            "        \"order\": \"asc\"\n" +
            "      }\n" +
            "    },\n" +
            "    {\n" +
            "      \"timestamp\": {\n" +
            "        \"order\": \"asc\"\n" +
            "      }\n" +
            "    }\n" +
            "  ],\n" +
            "  \"_source\": [\n" +
            "    \"ip_src_addr\",\n" +
            "    \"ip_dst_addr\",\n" +
            "    \"enrichments:ip_src_addr:asset_name\",\n" +
            "    \"enrichments:ip_dst_addr:asset_name\",\n" +
            "    \"enrichments:threat_type_alias\",\n" +
            "    \"enrichments:threat_name\",\n" +
            "    \"enrichments:threat_name_level\",\n" +
            "    \"timestamp\"\n" +
            "  ]\n" +
            "}";
    private static String searchAfterStr = "{\n" +
            "  \"size\": 10000,\n" +
            "  \"query\": {\n" +
            "    \"bool\": {\n" +
            "      \"filter\": [\n" +
            "        {\n" +
            "          \"range\": {\n" +
            "            \"timestamp\": {\n" +
            "              \"gte\": %s,\n" +
            "              \"lte\": %s\n" +
            "            }\n" +
            "          }\n" +
            "        }\n" +
            "      ]\n" +
            "    }\n" +
            "  },\n" +
            "  \"search_after\": [\n" +
            "    %s,\n" +
            "    %s\n" +
            "  ],\n" +
            "  \"sort\": [\n" +
            "    {\n" +
            "      \"uid\": {\n" +
            "        \"order\": \"asc\"\n" +
            "      }\n" +
            "    },\n" +
            "    {\n" +
            "      \"timestamp\": {\n" +
            "        \"order\": \"asc\"\n" +
            "      }\n" +
            "    }\n" +
            "  ],\n" +
            "  \"_source\": [\n" +
            "    \"ip_src_addr\",\n" +
            "    \"ip_dst_addr\",\n" +
            "    \"enrichments:ip_src_addr:asset_name\",\n" +
            "    \"enrichments:ip_dst_addr:asset_name\",\n" +
            "    \"enrichments:threat_type_alias\",\n" +
            "    \"enrichments:threat_name\",\n" +
            "    \"enrichments:threat_name_level\",\n" +
            "    \"timestamp\"\n" +
            "  ]\n" +
            "}";

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.print("args: \n" +
                    "args[0]: 请求IP，格式10.10.11.12或localhost, 例子: localhost\n" +
                    "args[1]: 开始某一天的时间，格式yyyy-MM-dd HH:mm:ss, 例子: 2020-06-08 01:00:00\n" +
                    "args[2]: 结束某一天的时间，格式yyyy-MM-dd HH:mm:ss, 例子: 2020-06-08 22:00:00\n" +
                    "执行示例： 导出2020.06.08到2020.06.10 威胁数据。\n" +
                    "java -jar traceListExport-jar-with-dependencies.jar  \"localhost\" \"2020-06-08 01:02:03\" \"2020-06-10 01:02:03\"\n");
            return;
        }

        String ip = args[0];
        String startTime = args[1];
        String endTime = args[2];

        try {
            Date parse = format.parse(startTime);
            long star = parse.getTime();
            Date parse1 = format.parse(endTime);
            long end = parse1.getTime();
            String[] s1 = startTime.split(" ");
            String[] split1 = s1[1].split(":");
            String[] split2 = s1[0].split("-");
            String startDate = split2[1] + split2[2] + split1[0];

            String[] s2 = endTime.split(" ");
            String[] split3 = s2[0].split("-");
            String[] split4 = s2[1].split(":");
            String endDate = split3[1] + split3[2] + split4[0];


            //获取时间区间
            List<String> strings = dateForEach(star, end, 1, "yyyy.MM.dd");

            StringBuilder stringBuilder = new StringBuilder();
            if (CollectionUtils.isNotEmpty(strings)){
                strings.forEach(s -> stringBuilder.append(String.format(indexStr,s)).append(","));
                stringBuilder.deleteCharAt(stringBuilder.lastIndexOf(","));
            }else {
                return;
            }

            String url = String.format(esHttpStr, ip, stringBuilder.toString());
            System.out.println("查询URL："+url);

            findData(url, star, end,startDate,endDate);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     *  获取时间戳之间天数
     * @param startDate
     * @param endDate
     * @param Flag
     * @param format
     * @return
     * @throws ParseException
     */
    private static List<String> dateForEach(Long startDate, Long endDate, Integer Flag, String format) throws ParseException{
        List<String> resultList = new ArrayList<>();

        format = StringUtils.isEmpty(format) ? "yyyyMMdd" :format;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(format);

        Date startDateTime = simpleDateFormat.parse(simpleDateFormat.format(startDate));
        Date endDateTime = simpleDateFormat.parse(simpleDateFormat.format(endDate));

        Calendar startCalender = Calendar.getInstance(), endCalendar = Calendar.getInstance();

        startCalender.setTime(startDateTime);
        endCalendar.setTime(endDateTime);

        if (startDateTime.compareTo(endDateTime) < 1){
            switch (Flag) {
                case 1:
                    while (true){
                        resultList.add(simpleDateFormat.format(startCalender.getTime()));
                        startCalender.add(Calendar.DAY_OF_MONTH,1);
                        if (startCalender.after(endCalendar)) break;
                    }
                    break;
                case 2:
                    while (true){
                        resultList.add(simpleDateFormat.format(startCalender.getTime()));
                        startCalender.add(Calendar.HOUR_OF_DAY,1);
                        if (startCalender.after(endCalendar)) break;
                    }
                    break;
                case 3:
                    while (true){
                        resultList.add(simpleDateFormat.format(startCalender.getTime()).substring(0,7));
                        startCalender.add(Calendar.MONTH,1);
                        if (startCalender.after(endCalendar)) break;
                    }
                    break;
            }
        }

        return resultList;
    }

    /**
     * 数据查询方法
     * @return
     */
    private static void findData(String url, long startTime, long endTime, String startDate, String endDate){
        try {
            String body = String.format(esBody, startTime, endTime);
            String result = postRequest(url, body);
            System.out.println("第1次！");

            JSONArray objects = Optional.ofNullable(JSON.parseObject(result))
                    .map(jsonObj -> jsonObj.getJSONObject("hits"))
                    .map(htsObj -> htsObj.getJSONArray("hits"))
                    .orElse(null);

            if (objects != null && objects.size() == 10000){
                JSONArray flagArray = null;

                int a = 2;
                do {
                    JSONObject jsonObject = null;
                    if (flagArray == null){
                        jsonObject = objects.getJSONObject(9999);
                    }else {
                        jsonObject = flagArray.getJSONObject(9999);
                        objects.addAll(flagArray);
                        if (objects.size() >= 400000){
                            System.out.println("分批写入：400000条");
                            List<String> strings = dataProcessing(objects);
                            exportDataToTXT(strings,startDate,endDate);
                            objects = new JSONArray();
                        }
                    }

                    JSONArray sort = jsonObject.getJSONArray("sort");

                    Object uid = sort.get(0);
                    Object timestamp = sort.get(1);

                    String format = String.format(searchAfterStr, startTime, endTime, uid, timestamp);
                    String res = postRequest(url, format);
                    System.out.println("第"+a+"次！");
                    a++;

                    flagArray = Optional.ofNullable(JSON.parseObject(res))
                            .map(jsonObj -> jsonObj.getJSONObject("hits"))
                            .map(htsObj -> htsObj.getJSONArray("hits"))
                            .orElse(null);

                }while (flagArray != null && flagArray.size() == 10000);

                if (flagArray != null && !flagArray.isEmpty()){
                    objects.addAll(flagArray);
                }

                String s = exportDataToTXT(dataProcessing(objects), startDate, endDate);
                System.out.println("文件路径："+s);
            }

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * 数据处理
     * @param data
     * @return
     */
    private static List<String> dataProcessing(JSONArray data){
        List<String> strList = Lists.newArrayList();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        data.parallelStream().forEach(json -> {
            JSONObject jsonObject = ((JSONObject) json).getJSONObject("_source");

            StringBuilder stringBuilder = new StringBuilder();

            //获取源ip
            String ipSrcAddr = jsonObject.getString("ip_src_addr");
            //获取源ip资产名称
            String srcAssetName = Objects.nonNull(jsonObject.getString("enrichments:ip_src_addr:asset_name")) ? jsonObject.getString("enrichments:ip_src_addr:asset_name") : "    ";
            //获取目的ip
            String ipDstAddr = jsonObject.getString("ip_dst_addr");
            //获取目的ip资产名称
            String dstAssetName = Objects.nonNull(jsonObject.getString("enrichments:ip_dst_addr:asset_name")) ? jsonObject.getString("enrichments:ip_dst_addr:asset_name") : "    ";
            //获取攻击类型
            String threatType = jsonObject.getString("enrichments:threat_type_alias");
            //获取攻击名称
            String threatName = jsonObject.getString("enrichments:threat_name");
            //获取攻击等级
            String level = jsonObject.getString("enrichments:threat_name_level");
            //获取攻击时间
            Long timestamp = jsonObject.getLong("timestamp");
            String time = simpleDateFormat.format(new Date(timestamp));

            String s = stringBuilder.append(ipSrcAddr).append(",").append(srcAssetName).append(",").append(ipDstAddr).append(",")
                    .append(dstAssetName).append(",").append(threatType).append(",").append(threatName).append(",")
                    .append(level).append(",").append(time).toString();
            strList.add(s);
        });

        return strList;
    }

    /**
     * @Description: 获取项目路径
     * @Author: liuhe
     * @Date: 2020/7/6 下午4:46
     * @Params: []
     * @Return: java.lang.String
     */
    private static String getPath() {
        String path = TraceListExport.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        if (System.getProperty("os.name").contains("dows")) {
            path = path.substring(1);
        }

        if (path.contains("jar")) {
            path = path.substring(0, path.lastIndexOf("."));
            return path.substring(0, path.lastIndexOf("/"));
        } else {
            return path.replace("target/classes/", "");
        }
    }

    /**
     * 数据写入csv
     * @param listFinal
     * @param dateStr
     * @param endTime
     * @return
     */
    private static String exportDataToTXT(List<String> listFinal, String dateStr, String endTime){
        String classPath = getPath();
        BufferedWriter bw = null;

        try {
            bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(classPath + File.separator + "威胁数据-" + dateStr + "-" + endTime + ".csv"),true),"UTF-8"));

            //输出标题
            if (outputFlag){
                String s1 = "源ip，源ip资产名称，目标ip，目标ip资产名称，攻击类型，攻击名称，攻击等级，攻击时间";
                bw.write(s1);
                bw.newLine();
                bw.flush();
                outputFlag = false;
            }

            if (CollectionUtils.isNotEmpty(listFinal)){
                for (String str : listFinal) {
                    if (str != null){
                        bw.write(str);
                        bw.newLine();
                        bw.flush();
                    }
                }
            }

            return classPath + File.separator + "威胁数据-" + dateStr + "-" + endTime + ".csv";
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (bw != null){
                try{
                    bw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return "生成失败！";
    }

    /**
     * @Description: 线程池调用查询
     * @Author: liuhe
     * @Date: 2020/7/6 下午4:48
     * @Params: []
     * @Return: void
     */
    private static String concurrentGetData(List<Map<String,Object>> maps){

        //获取线程池
        int val = maps.size();
        ExecutorService executorService = null;
        List<String> resultList = Lists.newArrayList();
        try {
            executorService = Executors.newFixedThreadPool(val);
            ExecutorCompletionService<String> stringExecutorCompletionService = new ExecutorCompletionService<>(executorService);

            maps.forEach(iMap -> stringExecutorCompletionService.submit(new FindCallable(
                    (String) iMap.get("url"),
                    (Long) iMap.get("startTime"),
                    (Long) iMap.get("endTime"),
                    (String) iMap.get("startDate"),
                    (String) iMap.get("endDate")
            )));

            while (val-- > 0){
                resultList.add(stringExecutorCompletionService.take().get());
            }

            if (CollectionUtils.isNotEmpty(resultList)){
                return "文件路径为: " + resultList.get(0);
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            if (Objects.nonNull(executorService)){
                try {
                    executorService.shutdown();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }

        return "生成失败！";
    }

    /**
     * @Description: 线程实现方法  需要返回值实现Callable
     * @Author: liuhe
     * @Date: 2020/7/6 下午4:51
     * @Params:
     * @Return:
     */
    private static class FindCallable implements Callable<String>{

        //请求路径
        private String url;
        //开始时间
        private long startTime;
        //结束时间
        private long endTime;
        //开始时间字符串
        private String startDate;
        //结束时间字符串
        private String endDate;

        public FindCallable(String url, long startTime, long endTime, String startDate, String endDate){
            this.url = url;
            this.startTime = startTime;
            this.endTime = endTime;
            this.startDate = startDate;
            this.endDate = endDate;
        }

        @Override
        public String call() throws Exception {

            String resultStr = "";

            try {
                String body = String.format(esBody, startTime, endTime);
                String result = postRequest(url, body);

                JSONArray objects = Optional.ofNullable(JSON.parseObject(result))
                        .map(jsonObj -> jsonObj.getJSONObject("hits"))
                        .map(htsObj -> htsObj.getJSONArray("hits"))
                        .orElse(null);

                if (objects != null && objects.size() == 10000){
                    JSONArray flagArray = null;

                    do {
                        JSONObject jsonObject = null;
                        if (flagArray == null){
                            jsonObject = objects.getJSONObject(9999);
                        }else {
                            jsonObject = flagArray.getJSONObject(9999);
                            objects.addAll(flagArray);
                            if (objects.size() >= 400000){
                                System.out.println("分批写入：400000条");
                                List<String> strings = dataProcessing(objects);
                                exportDataToTXT(strings,startDate,endDate);
                                objects = new JSONArray();
                            }
                        }

                        JSONArray sort = jsonObject.getJSONArray("sort");

                        Object uid = sort.get(0);
                        Object timestamp = sort.get(1);

                        String format = String.format(searchAfterStr, startTime, endTime, uid, timestamp);
                        String res = postRequest(url, format);

                        flagArray = Optional.ofNullable(JSON.parseObject(res))
                                .map(jsonObj -> jsonObj.getJSONObject("hits"))
                                .map(htsObj -> htsObj.getJSONArray("hits"))
                                .orElse(null);

                    }while (flagArray != null && flagArray.size() == 10000);

                    if (flagArray != null && !flagArray.isEmpty()){
                        objects.addAll(flagArray);
                    }

                    resultStr = exportDataToTXT(dataProcessing(objects), startDate, endDate);
                }
            }catch (Exception e){
                e.printStackTrace();
            }

            return resultStr;
        }
    }
}
