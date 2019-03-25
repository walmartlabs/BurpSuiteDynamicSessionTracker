/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/

package burp;

import static burp.BurpExtender.stdout;

public class TrackCookie {

    public static String selectedCookieName = null;

    public static void trackThisCookie(IHttpRequestResponse message, IContextMenuInvocation invocation, int[] bounds){
        if (invocation.getInvocationContext() == 2 || invocation.getInvocationContext() == 0) {

            selectedCookieName = new String(message.getRequest()).substring(bounds[0], bounds[1]);
            selectedCookieName = selectedCookieName.trim();
            stdout.println("[+] You are now tracking this cookie: " + selectedCookieName);

        } else if (invocation.getInvocationContext() == 3){

            selectedCookieName = new String(message.getResponse()).substring(bounds[0], bounds[1]);
            selectedCookieName = selectedCookieName.trim();
            stdout.println("[+] You are now tracking this cookie: " + selectedCookieName);

        } else {
            stdout.println("[-] The invocation context did not match anything known?");
            stdout.println("[*] The invocation context is : " + invocation.getInvocationContext());
        }
    }






}//class