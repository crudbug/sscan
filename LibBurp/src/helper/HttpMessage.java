package helper;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponseWithMarkers;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import log.Logger;


public class HttpMessage {
    
    public static byte[] NEWLINE_WIN = "\r\n".getBytes();
    public static byte[] NEWLINE_NIX = "\n".getBytes();
    
    
    public static long makeRequest(IBurpExtenderCallbacks iburp, IHttpRequestResponse message, String request) {
        long startTime = new Date().getTime();
        iburp.makeHttpRequest(message.getHttpService(), iburp.getHelpers().stringToBytes(request));
        return new Date().getTime() - startTime;
    }

    
    public static String getResponseHeaderValue(IBurpExtenderCallbacks iburp, byte[] response, String headerName) {
        List<String> headers = iburp.getHelpers().analyzeResponse(response).getHeaders();
        Pattern needle = Pattern.compile("^"+headerName+":\\s*(.*)$", Pattern.CASE_INSENSITIVE);

        for (String header : headers) {
            Matcher matcher = needle.matcher(header);
            if (matcher.matches()) {
                return matcher.group(1);
            }
        }

        return null;
    }
    

    public static String getMethod(IHttpRequestResponse currentMessageInfo) throws Exception {
        return getMethod(currentMessageInfo.getRequest());
    }
    
    public static String getMethod(byte[] request) throws Exception {
        return new String(request).split("\\s", 2)[0];
    }
        
    public static String getPath(IBurpExtenderCallbacks iburp, byte[] request) throws MalformedURLException {
        return iburp.getHelpers().bytesToString(request).split("\\s", 3)[1];
    }

   
    public static List<int[]> getMatches(byte[] haystack, byte[] needle, IExtensionHelpers helper) {
        List<int[]> matches = new ArrayList<>();
       
        int start = 0;
        while (start < haystack.length) {
            start = helper.indexOf(haystack, needle, true, start, haystack.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[]{start, start + needle.length});
            start += needle.length;
        }

        return matches;
    } 

    public static List<int[]> getMatches(String haystack, String[] needles) {
        List<int[]> matches = new ArrayList<>();
        for (String needle : needles) {
            matches.addAll(getMatches(haystack, needle));
        }
        return matches;
    }

    public static List<int[]> getMatches(String haystack, String needle) {
        List<int[]> matches = new ArrayList<>();
        Pattern pattern = Pattern.compile(needle);
        Matcher matcher = pattern.matcher(haystack);
         
        while (matcher.find()) {
            matches.add(new int[]{matcher.start(0), matcher.end(0)});
        }

        return matches;
    }

    public static List<String> parseMarkers(byte[] rawData, List<int[]> markers) {
        return getMarkers(markers, rawData, false);
    }

    
    public static List<String> getResponseMarkers(IHttpRequestResponseWithMarkers message) {
        return getMarkers(message.getResponseMarkers(), message.getResponse(), false);
    }

    public static List<String> getRequestMarkers(IHttpRequestResponseWithMarkers message) {
        return getMarkers(message.getRequestMarkers(), message.getRequest(), false);
    }

    public static List<String> getExtendedResponseMarkers(IHttpRequestResponseWithMarkers requestResponse) {
        return getExtendedMarkers(requestResponse, false);
    }
    
    public static List<String> getExtendedRequestMarkers(IHttpRequestResponseWithMarkers requestResponse) {
        return getExtendedMarkers(requestResponse, true);
    }

    public static String getCustomMarkers(IHttpRequestResponse requestResponse, int[] bounds, boolean isRequest) {
        List<String> markers;
        
        if (isRequest) {
            markers = HttpMessage.getMarkers(Arrays.asList(bounds), requestResponse.getRequest(), false);
        } else {
            markers = HttpMessage.getMarkers(Arrays.asList(bounds), requestResponse.getResponse(), false);
        }

        if (markers.size() == 1) {
            return markers.get(0);
        }
        else {
            return "";
        }
    }
    
    
    
    /**
     * Markers might appear in the header or body. Because different line endings
     * are possible, we need to search for the first of them
     * @param response
     * @param iburp
     * @return 
     */
    public static List<String> getResponseMarkerLine(IHttpRequestResponseWithMarkers response, IBurpExtenderCallbacks iburp) {
        return getMarkerLineHelper(response.getResponse(), response.getResponseMarkers(), iburp);
    }
    
    
    public static List<String> getRequestMarkerLine(IHttpRequestResponseWithMarkers request, IBurpExtenderCallbacks iburp) {
        return getMarkerLineHelper(request.getRequest(), request.getRequestMarkers(), iburp);
    }

    private static List<String> getMarkers(List<int[]> allMarkers, byte[] rawData, boolean extended) {
        int EXTRA = 50;
        List<String> markers = new ArrayList<>();
        int start;
        int stop;

        for (int[] markerIndex : allMarkers) {
            if (extended) {
                start = markerIndex[0] - EXTRA > 0 ? markerIndex[0] - EXTRA : 0;
                stop = markerIndex[1] + EXTRA < rawData.length ? markerIndex[1] + EXTRA : rawData.length - 1;
            } else {
                start = markerIndex[0];
                stop = markerIndex[1];
            }

            byte[] marker = Arrays.copyOfRange(rawData, start, stop);
            try {
                markers.add(new String(marker, "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                Logger log = Logger.getInstance();
                log.err("Failed to obtain a marker", ex);
            }
        }

        return markers;
    }

    /**
     *
     * @param requestResponse
     * @param extended
     * @return
     */
    private static List<String> getExtendedMarkers(IHttpRequestResponseWithMarkers requestResponse, boolean isRequest) {
        List<String> markers;

        if (isRequest) {
            markers = getMarkers(requestResponse.getRequestMarkers(), requestResponse.getRequest(), true);
        }        
        else {
            markers = getMarkers(requestResponse.getResponseMarkers(), requestResponse.getResponse(), true);
        }
        
        return markers;
    }

    public static List<int[]> orderMarkers(List<int[]> markers) {
        Collections.sort(markers, new MarkerComparator());
        return markers;
    }

    static private class MarkerComparator implements Comparator<int[]> {

        @Override
        public int compare(int[] o1, int[] o2) {
            return Integer.compare(o1[0], o2[0]);
        }
    }
    
    public static String getResponseBodyStr(IBurpExtenderCallbacks iburp, IHttpRequestResponse response) {
        return iburp.getHelpers().bytesToString(getResponseBody(iburp, response));
    }
    
    public static byte[] getResponseBody(IBurpExtenderCallbacks iburp, IHttpRequestResponse response) {
        int bodyOffset = iburp.getHelpers().analyzeResponse(response.getResponse()).getBodyOffset();
        return Arrays.copyOfRange(response.getResponse(), bodyOffset, response.getResponse().length);
    }
    
    
    
    private static void debugByteArray(byte[] in, int start, int end) {
            byte[] split = Arrays.copyOfRange(in, start, end);
            
            StringBuilder sb = new StringBuilder(split.length * 7);
            for(byte b: split) {
                sb.append((char) b).append(" : ").append(String.format("%02x", b & 0xff)).append("\n");
            }
            
            Logger.getInstance().trace(sb.toString());
    }

}
