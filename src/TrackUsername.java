/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import java.util.List;

import static burp.BurpExtender.stdout;
import static burp.TrackCookie.selectedCookieName;
import static burp.BurpExtender.helpers;

public class TrackUsername{

    public static String selectedUserName = null;

    public static void trackThisUsername(IHttpRequestResponse message, IContextMenuInvocation invocation, int[] bounds){
        if (invocation.getInvocationContext() == 2 || invocation.getInvocationContext() == 0) {

            selectedUserName = new String(message.getRequest()).substring(bounds[0], bounds[1]);
            selectedUserName = selectedUserName.trim();
            stdout.println("[+] You are now tracking this username: " + selectedUserName);

        } else if (invocation.getInvocationContext() == 3){
            selectedUserName = new String(message.getResponse()).substring(bounds[0], bounds[1]);
            selectedUserName = selectedUserName.trim();
            stdout.println("[+] You are now tracking this username: " + selectedUserName);

        } else {
            stdout.println("[-] The invocation context did not match anything known?");
            stdout.println("[*] The invocation context is : " + invocation.getInvocationContext());
        }
    }

    public static String getFirstCookieVal(IHttpRequestResponse message, IContextMenuInvocation invocation){
        String firstCookieVal = null;

        if(invocation.getInvocationContext() == 2 || invocation.getInvocationContext() == 0){
            IRequestInfo request = helpers.analyzeRequest(message);
            for (String str : request.getHeaders()){
                if(str.matches("^Cookie:.*") && str.matches((".*" + selectedCookieName + ".*"))){
                    String[] strArr = str.split("\\s" + selectedCookieName);
                    firstCookieVal = strArr[1].split("=")[1];
                    firstCookieVal = firstCookieVal.split(";|\\s|\\n")[0];

                }
            }
        } else if (invocation.getInvocationContext() == 3){
            IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
            List<ICookie> cookies = responseInfo.getCookies();

            for (ICookie c : cookies) {
                if (c.getName().equals(selectedCookieName)){
                    firstCookieVal = c.getValue();
                }
            }
        } else {
            stdout.println("[-] The invocation context did not match anything known?");
            stdout.println("[*] The invocation context is : " + invocation.getInvocationContext());
        }

        if(firstCookieVal == null){
            firstCookieVal = "placeholder";
        }
        stdout.println("[*] Using firstCookieVal " + firstCookieVal);
        return firstCookieVal;
    }



}//class