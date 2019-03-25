# BurpDynamicSessionTracker (BDST)
### Burp extension to track dynamic session cookies back to their source easily and swap between sessions.


## Prereqs

The only thing you need is to have BurpSuite, this plugin should not require Pro as I do not utilize the active scan feature at all. You can download the JAR here or compile yourself.
Install the plugin in BurpSuite by following the steps here: https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite


## Setup

**The following must be set for tracking to start tracking.** I recommend capturing a login request and doing these steps with that request.

**Set a session cookie name** to track by highlighting the cookie name and selecting *"Track this session cookie"*

![Set Session Cookie](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/track_this_session_cookie.png)


**Set a username** to track (e.g. intercept a login POST and select the email parameter) by highlighting the username and selecting *"Track this username"*

![Set Username](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/track_this_username.png)


_optional_ **Only track in-scope items** If you wish to only track requests that meet BurpSuite's "In target scope" check enable this option. This may be useful if you observe a performance impact as it may reduce the number of messages being parsed.

![Only Track In-Scope](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/only_track_in_scope.png)

_It is recommended that you turn this setting on if browsing multiple sites that use the same session cookie name even though it should never become an issue_


Now you are tracking a chain of session ID's by the cookie name. You can start new chains by highlighting a different username and performing step 2 as many times as you like.
There is one caveat that the cookie name must remain the same, but this should never be an issue when assessing a single application which is the intended use case.

_Also note that you need to have a **new unique cookie value** for each additional username session chain to track. This is because the plugin will automatically grab the value within the request you are selecting a new username from.
Generally this should not be an issue in a new browser tab, or after a logout as an application normally will provide a new session ID._


## Usage

**You have tracked a session, or multiple, and want to see what user a given request was performed as**:
1. Highlight the _cookie value_ you wish to search and select *"What user is this?"*

![What User Is This](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/what_user_is_this1.png)

![User Popup](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/what_user_is_this2.png)


**You want to switch to a different tracked session.** Such as swapping between users on a repeater tab. You can automatically replace the value with the latest cookie of the desired session by doing the following:
1. Highlight the cookie text for the session cookie you want to change.
2. Right click and select *"Switch Session ID"* then pick the tracked user to *Switch to*
3. Your request will have the highlighted text changed to the latest tracked cookie for the selected user.

![Switch Session ID](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/switch_session_id.png)


**You want to see what your currently tracked data is**:
1. This is displayed on the GUI tab which refreshes its text each time a new cookie value is added to a chain.

![GUI Tab](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/gui_tab_example.png)


**You want to add a value manually to a chain** _this should not be needed often_:
1. Highlight the cookie value you need to add.
2. Right click and select *"Manually add value to chain"* and pick the desired username.

![Manually Add Cookie Value](https://www.appsecdojo.com/img/burp-dynamic-session-tracker/manually_add_to_chain.png)


## Troubleshooting

**My session cookie isn't getting tracked**
_Make sure you have selected a username._ When you select a username BDST will attempt to get the current value of the cookie from the request you are setting the username from. **This won't always succeed and it will put 'placeholder' in the chain instead.**
Unfortunately, since the logic to keep chains separate while tracking multiple user sessions at once works by evaluating the cookie value in a request and putting all new unique values in corresponding responses in this case you need to manually add your cookie.
To do this highlight the cookie value in your most recent request for the desired session and right click then select *"Manually add value to chain: {Desired Username}"*. Then once you initiate new requests with that cookie which prompt a new cookie value the tracking will pick back up.

**I'm getting values from other sites who use the same cookie name somehow**
While this shouldn't happen I included an option to only check for new values in responses that are from in-scope requests.
To enable this right click in a request or response and select *"Only track in scope items?"*
_To disable do right click and select "Track out of scope items?"_

**Where can I see what I have tracked?**
There is a tab which will contain the name of the cookie you are tracking on the left and a breakdown of each chain's username and associated values on the right.

**I need to delete all of the data I have tracked and set a new cookie value**
There is a menu option when you right click that will delete everything. Be aware it does indeed delete **_EVERYTHING_** the plugin was storing. So use accordingly.
Right click in a message and select _"Clear all session tracking items"_ you will be prompted to confirm before the delete happens.

**I started my project in Burp back up but the data is gone**
Sorry this is a planned feature enhancement (no ETA) to store the data in a file on disk or something to support keeping the data past a single session. This requires further research on my part.


## License

This project is licensed under the Apache 2.0 license - see the [LICENSE.md](LICENSE.md) file for details.