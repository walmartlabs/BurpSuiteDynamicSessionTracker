/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import javax.swing.*;
import java.util.List;

import static burp.BurpExtender.stdout;
import static burp.TrackedChains.chainList;
import static burp.BurpExtender.gui;


public class FindUser {

    private static Boolean cookieFound = false;
    private static String originUser = null;
    public static String selectedCookieVal = null;


    public static void getUserFromSessID(IHttpRequestResponse message, IContextMenuInvocation invocation, int[] bounds) {
        if (invocation.getInvocationContext() == 2 || invocation.getInvocationContext() == 0) {
            selectedCookieVal = new String(message.getRequest()).substring(bounds[0], bounds[1]);
            selectedCookieVal = selectedCookieVal.trim();

        } else if (invocation.getInvocationContext() == 3){
            selectedCookieVal = new String(message.getResponse()).substring(bounds[0], bounds[1]);
            selectedCookieVal = selectedCookieVal.trim();

        } else {
            stdout.println("[-] The invocation context did not match anything known?");
            stdout.println("[*] The invocation context is : " + invocation.getInvocationContext());
            return;
        }

        if (!cookieFound) {
            for (List<String> l : chainList) {
                for (String entry : l) {
                    if (!cookieFound && entry.contains(selectedCookieVal)) {
                        stdout.println("[+] Found your cookie!");
                        cookieFound = true;
                        originUser = l.get(0);
                    }
                }
            }
        }

        if (!cookieFound) {
            JOptionPane.showMessageDialog(gui.frame, "The cookie was not found!");
            stdout.println("[-] The cookie isn't in any tracked lists!");
        }

        if (originUser != null) {
            JOptionPane.showMessageDialog(gui.frame, "The user for this cookie is: " + originUser);
            stdout.println("[+] The user for this cookie is: " + originUser);
        }

        //Set the logic controls back
        originUser = null;
        cookieFound = false;
    }

}//class