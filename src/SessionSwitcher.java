/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import java.util.ArrayList;
import java.util.List;

import static burp.BurpExtender.helpers;
import static burp.BurpExtender.stdout;
import static burp.TrackedChains.chainList;

public class SessionSwitcher {

    private static List<String> deDuplicatedUsers = new ArrayList<String>();

    public static String[] pickNewSession(IHttpRequestResponse message, byte invocation){

        for (List<String> l : chainList) {
            String entry = l.get(0);

            if (!deDuplicatedUsers.contains(entry)){
                deDuplicatedUsers.add(entry);
                continue;
            }
        }

        String[] strArr = new String[deDuplicatedUsers.size()];

        if(invocation == 0){
            int i = 0;
            for (String str: deDuplicatedUsers) {
                strArr[i] = str;
                i++;
            }
        }

        if(invocation == 2){
            int i = 0;
            for (String str: deDuplicatedUsers) {
                strArr[i] = str;
                i++;
            }
        }

        deDuplicatedUsers.clear();
        return strArr;
    }


    public static byte[] changeSessionValue(IHttpRequestResponse message, int[] bounds, String sessionToSwapTo){
        String currentCookieText = new String(message.getRequest()).substring(bounds[0], bounds[1]);
        String editedRequest = helpers.bytesToString(message.getRequest());

        editedRequest = editedRequest.replace(currentCookieText, getLatestCookie(sessionToSwapTo));
        byte[] toReturn = editedRequest.getBytes();

        return toReturn;
    }

    private static String getLatestCookie(String lookup){
        for (List<String> l : chainList) {
            if(l.get(0).equals(lookup)){
                stdout.println("[+] Found replacement cookie!");
                return l.get(l.size() - 1);
            }
        }

        stdout.println("[-] Somehow we got no cookie??");
        return null;
    }


}//class