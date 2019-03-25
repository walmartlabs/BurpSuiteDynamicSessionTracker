/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/

package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.List;

import static burp.TrackCookie.selectedCookieName;
import static burp.TrackUsername.selectedUserName;
import static burp.TrackedChains.checkCookieValExists;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    public final static burp.DynamicSessionTrackerGUI gui = new burp.DynamicSessionTrackerGUI();
    private IBurpExtenderCallbacks _callbacks;
    protected static IExtensionHelpers helpers;

    public static PrintWriter stdout;

    protected static String requestCookieVal = null;
    protected static String responseCookieVal = null;

    public static Boolean isInScopeOnly = false;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        _callbacks = callbacks;

        callbacks.setExtensionName("Burp Dynamic Session Tracker");
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(gui);


        stdout = new PrintWriter(callbacks.getStdout(), true);
        helpers = callbacks.getHelpers();

        //Create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                gui.statusTextArea.setEditable(false);
                gui.statusTextArea.setText("You are currently tracking this cookie: " + selectedCookieName + "\n\n\n");
                gui.splitPane.setLeftComponent(gui.statusTextArea);

                gui.ourSessionsTextArea.setEditable(false);
                gui.ourSessionsTextArea.setLineWrap(true);
                gui.splitPane.setRightComponent(gui.ourSessionsTextArea);

                _callbacks.customizeUiComponent(gui.splitPane);
                _callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse requestResponse) {

        try {

            if(selectedUserName != null && selectedCookieName != null && !selectedCookieName.isEmpty() && !messageIsRequest){
                requestCookieVal = getReqVal(requestResponse);
                responseCookieVal = getResVal(requestResponse);

                if (responseCookieVal != null && requestCookieVal != null){
                    checkCookieValExists(requestCookieVal, responseCookieVal);
                    gui.updateSessListArea();
                }
            }

        } catch (Exception e) {
            stdout.println("[-] In the messaging processing exception!");
            e.printStackTrace(stdout);
        }
    }


    private String getReqVal(IHttpRequestResponse messageInfo){
        IRequestInfo request = helpers.analyzeRequest(messageInfo);

        if(isInScopeOnly && !_callbacks.isInScope(request.getUrl())){
                return null; // We shouldn't need to return null on response parsing since req/res pairs would set
                         // req val to null and fail next logic gate
        }

        for(String str : request.getHeaders()){
            if(str.matches("^Cookie:.*") && str.matches((".*" + selectedCookieName + ".*"))){
                String[]strArr = str.split("\\s" + selectedCookieName);
                requestCookieVal = strArr[1].split("=")[1];
                requestCookieVal = requestCookieVal.split(";|\\s|\\n")[0];
            }
        }
        return requestCookieVal;
    }


    private String getResVal(IHttpRequestResponse messageInfo){
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());

        List<ICookie> cookies = responseInfo.getCookies();

        for (ICookie c : cookies) {
            if (c.getName().equals(selectedCookieName)){
                responseCookieVal = c.getValue();
            }
        }

        return responseCookieVal;
    }

    // This was necessary to implement ITab
    @Override
    public String getTabCaption(){
        return "Dynamic Session Tracker";
    }
    // This was necessary to implement ITab
    @Override
    public Component getUiComponent(){
        return gui.splitPane;
    }


}//class
