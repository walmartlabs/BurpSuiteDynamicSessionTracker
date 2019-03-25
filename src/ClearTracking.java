/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import static burp.BurpExtender.gui;
import static burp.BurpExtender.stdout;
import static burp.TrackedChains.chainList;
import static burp.TrackCookie.selectedCookieName;
import static burp.FindUser.selectedCookieVal;
import static burp.TrackUsername.selectedUserName;

public class ClearTracking {

    public static void clearTrackedData(){
        try {
            if(gui.confirmDeletePopup() == 0){
                selectedCookieName = null;
                selectedCookieVal = null;
                selectedUserName = null;
                chainList.clear();
                gui.nullTextArea();
                gui.updateSessListArea();
                stdout.println("[*] Everything has been cleared!");
            }else {
                stdout.println("[*] Did not delete data");
            }

        } catch (Exception ex) {
            stdout.println("[-] In clear URL and tracked sessions exception");
            ex.printStackTrace(stdout);
        }
    }



}//class