/*Copyright (c) 2017-present, Walmart Inc.
This source code is licensed under the Apache 2.0 license found
in the LICENSE.md file in the root directory of this source tree.*/


package burp;

import javax.swing.*;
import javax.swing.JOptionPane;
import java.awt.event.*;
import java.util.Arrays;
import java.util.List;

import static burp.BurpExtender.*;
import static burp.TrackUsername.*;
import static burp.TrackCookie.trackThisCookie;
import static burp.TrackCookie.selectedCookieName;
import static burp.FindUser.getUserFromSessID;
import static burp.SessionSwitcher.pickNewSession;
import static burp.SessionSwitcher.changeSessionValue;
import static burp.ClearTracking.clearTrackedData;
import static burp.TrackedChains.*;

public class DynamicSessionTrackerGUI implements IContextMenuFactory {

    // GUI Stuff
    public final JFrame frame = new JFrame();
    public final JSplitPane splitPane = new JSplitPane();
    public final JTextArea statusTextArea = new JTextArea();
    public final JTextArea ourSessionsTextArea = new JTextArea();


    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        if(invocation==null) return null;
        JMenuItem SessionTrackerMenu = new JMenu("Dynamic Session Tracker");

        final IHttpRequestResponse message = invocation.getSelectedMessages()[0];
        final int[] bounds = invocation.getSelectionBounds();

        try {
            if (selectedCookieName == null && message != null && bounds != null && bounds.length >= 2) {

                JMenuItem trackCookieMenu = new JMenuItem("Track this session cookie");
                trackCookieMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {  //Annoying way to get the highlighted text from msg body
                        trackThisCookie(message, invocation, bounds);
                        updateTextArea();
                    }
                });
                SessionTrackerMenu.add(trackCookieMenu);
            }

            if (selectedCookieName != null && message != null && bounds != null && bounds.length >= 2 && selectedCookieName != null) {
                JMenuItem userQueryMenu = new JMenuItem("What user is this?");
                userQueryMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        getUserFromSessID(message, invocation, bounds);
                        updateTextArea();
                    }
                });
                SessionTrackerMenu.add(userQueryMenu);
            }

            if (selectedCookieName != null && message != null && bounds != null && bounds.length >= 2) {

                JMenuItem trackUsernameMenu = new JMenuItem("Track this username");
                trackUsernameMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {  //Annoying way to get the highlighted text from msg body
                        trackThisUsername(message, invocation, bounds);
                        trackNewUsername(selectedUserName, getFirstCookieVal(message, invocation));
                        updateTextArea();
                    }
                });
                SessionTrackerMenu.add(trackUsernameMenu);
            }

            if (selectedCookieName != null && message != null && chainList != null && (invocation.getInvocationContext() == 0 || invocation.getInvocationContext() == 2)){
                JMenu SwitchSessionID = new JMenu("Switch Session ID");
                for (String str : pickNewSession(message, invocation.getInvocationContext())) {
                    JMenuItem mItemToAdd = new JMenuItem("Switch to: " + str);
                    mItemToAdd.setActionCommand(str);
                    mItemToAdd.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            String idToSwap = e.getActionCommand();
                            message.setRequest(changeSessionValue(message,bounds,idToSwap));
                        }
                    });
                    SwitchSessionID.add(mItemToAdd);
                }
                SessionTrackerMenu.add(SwitchSessionID);
            }

            if (selectedCookieName != null && message != null && chainList != null && (invocation.getInvocationContext() == 0 || invocation.getInvocationContext() == 2)) {
                JMenu manuallyAddSessID = new JMenu("Manually add value to chain");
                for (String str : pickNewSession(message, invocation.getInvocationContext())){
                    JMenuItem ItemToAdd = new JMenuItem("Add to: " + str);
                    ItemToAdd.setActionCommand(str);
                    ItemToAdd.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            String userToAddTo = e.getActionCommand();
                            String sessIdToAdd = parseMessage(message, invocation, bounds);

                            manualAddToChain(userToAddTo, sessIdToAdd);
                            updateSessListArea();
                        }
                    });
                    manuallyAddSessID.add(ItemToAdd);
                }
                SessionTrackerMenu.add(manuallyAddSessID);
            }


            if (message != null && (selectedUserName != null || selectedCookieName != null || !chainList.isEmpty())) {
                //Button to clear the tracked lists
                JMenuItem clearDataMenu = new JMenuItem("Clear all session tracking settings");
                clearDataMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        clearTrackedData();
                        updateTextArea();
                        updateSessListArea();
                    }
                });
                SessionTrackerMenu.add(clearDataMenu);
            }

/*            if (message != null){
                JMenuItem debugLogMenu = new JMenuItem("Print debug log");
                debugLogMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        printDebugLogs();
                    }
                });
                SessionTrackerMenu.add(debugLogMenu);
            }*/

            if (message != null && !isInScopeOnly){
                final JCheckBoxMenuItem inScopeOnly = new JCheckBoxMenuItem("Only track in scope items?");
                inScopeOnly.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        onlyInScope();
                    }
                });
                SessionTrackerMenu.add(inScopeOnly);
            }

            if (message != null && isInScopeOnly) {
                final JCheckBoxMenuItem inScopeOnly = new JCheckBoxMenuItem("Track out of scope items?");
                inScopeOnly.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        onlyInScope();
                    }
                });
                SessionTrackerMenu.add(inScopeOnly);
            }


        }catch (Exception ex){
            ex.printStackTrace(stdout);
        }
        return Arrays.asList(SessionTrackerMenu);
    }




    // GUI Helpers
    public void nullTextArea(){
        try{
            statusTextArea.setText("You are currently tracking this cookie: " + selectedCookieName + "\n\n\n");
            stdout.println("[+] Text fields nullified!");
        }catch (Exception e){
            stdout.println("[-] Failed to nullify text fields");
            e.printStackTrace(stdout);
        }
    }

    public void updateTextArea(){
        try{
            statusTextArea.setText("You are currently tracking this cookie: " + selectedCookieName + "\n\n\n");
            stdout.println("[+] Text fields updated!");
        }catch (Exception e){
            stdout.println("[-] Failed to update text fields");
            e.printStackTrace(stdout);
        }
    }

    public void updateSessListArea(){
        try{
            String sessionsStr = new String();
            for (List<String> l : chainList) {
                sessionsStr = sessionsStr + "Username: " + l.get(0) + "\n";
                for (String s : l) {
                    sessionsStr = sessionsStr + s + ", ";
                }
                sessionsStr = sessionsStr + "\n\n";
            }

            ourSessionsTextArea.setText("Our current sessions: " + "\n\n" + sessionsStr);
        }catch (Exception e){
            stdout.println("[-] Failed to update session list text");
            e.printStackTrace(stdout);
        }
    }


    public static Integer confirmDeletePopup(){
        Object[] options = {"Confirm", "Cancel"};
        int i = JOptionPane.showOptionDialog(null, "Do you want to clear all session data?", "Dynamic Session Tracker", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]);
        return i;
    }


    public static Integer usernameAlreadyTracked(){
        Object[] options = {"Overwrite", "Cancel"};
        int i = JOptionPane.showOptionDialog(null, "The requested username is already being tracked. Would you like to overwrite?", "Dynamic Session Tracker", JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]);
        return i;
    }

    private void onlyInScope(){
        if (!isInScopeOnly){
            stdout.println("[+] Enabling in scope only");
            isInScopeOnly = true;
        } else {
            stdout.println("[+] Disabling in scope only");
            isInScopeOnly = false;
        }
    }

/*    public static void printDebugLogs(){
        for (List<String> l : chainList) {
            stdout.println(l);
        }
    }*/


}// Class