/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import java.util.ArrayList;
import java.util.List;

import static burp.BurpExtender.*;

public class TrackedChains {
    public static List<List<String>> chainList = new ArrayList<List<String>>();

    public static void trackNewUsername(String username, String firstCookieVal){
        for (int i = 0; i < chainList.size(); i++) {
            if(chainList.get(i).get(0).equals(username)){
                try{
                    stdout.println("[-] This username is already tracked");
                    if(checkOverwrite()) {
                        deleteList(chainList.get(i));
                        createList(username, firstCookieVal);
                    }
                    return;
                } catch (Exception e){
                    stdout.println("[-] In the trackNewUsername exception");
                    e.printStackTrace(stdout);
                }
            }
        }
        for (List<String> l : chainList) {

        }
        createList(username, firstCookieVal);
        stdout.println("[+] This username was not found we created a new list!");
    }

    public static void checkCookieValExists(String reqCookieVal, String resCookieVal){

        if(resCookieVal.length() <= 3){
            requestCookieVal = null;
            responseCookieVal = null;
            return;
        }

        for (List<String> l : chainList){
            for (String s : l){
                if (reqCookieVal != null && s.equals(reqCookieVal) && !l.contains(resCookieVal) && resCookieVal != null){
                    stdout.println("[+] Adding resCookieValue of: " + resCookieVal + " for username: " + l.get(0));
                    l.add(resCookieVal);
                    requestCookieVal = null;
                    responseCookieVal = null;
                    return;
                } else if (reqCookieVal != null && resCookieVal != null && l.contains(reqCookieVal) && l.contains(resCookieVal)){
                    //stdout.println("[*] The req and res cookie values are already in a list!");
                    requestCookieVal = null;
                    responseCookieVal = null;
                    return;
                }
            }
         }
    }

    public static void manualAddToChain(String userToAddTo, String strToAdd){
        for (List<String> l : chainList){
            if (l.get(0).equals(userToAddTo))
                l.add(strToAdd);
            stdout.println("[+] Added the session ID: " + strToAdd + "manually to user: " + userToAddTo);
        }
    }

    private static void deleteList(List<String> delList){
        try{
            stdout.println("[+] Deleting the list for user " + delList.get(0));
            chainList.remove(delList);
        } catch (Exception e) {
            stdout.println("[-] In the delete list exception");
            e.printStackTrace(stdout);
        }
    }

    private static void createList(String userToTrack, String firstCookie){
        List<String> tempList = new ArrayList<String>();
        tempList.add(0, userToTrack);
        tempList.add(firstCookie);
        stdout.println("[+] Created a new list");

        chainList.add(tempList);
        stdout.println("[+] Added the new list to the chainList");
    }

    private static Boolean checkOverwrite(){
        Boolean doOverwrite = false;

        if(gui.usernameAlreadyTracked() == 0){
            doOverwrite = true;
        }else{
            doOverwrite = false;
        }
        return doOverwrite;
    }

    public static String parseMessage(IHttpRequestResponse message, IContextMenuInvocation invocation, int[] bounds){

        if (invocation.getInvocationContext() == 0 || invocation.getInvocationContext() == 2){
            String reqString = new String(message.getRequest()).substring(bounds[0], bounds[1]);
            return reqString;
        } else if (invocation.getInvocationContext() == 1 || invocation.getInvocationContext() == 3){
            String resString = new String(message.getResponse()).substring(bounds[0], bounds[1]);
            return resString;
        }

        stdout.println("[-] Invocation did not match req or res?!");
        return null;
    }


} // class