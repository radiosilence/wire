#!/usr/bin/osascript

-- Authorize more tokens in Zed
on run
    tell application "System Events"
        -- Check if Zed is running
        if not (exists process "Zed") then
            display dialog "Zed is not running" buttons {"OK"} default button "OK"
            return
        end if
        
        -- Bring Zed to front
        tell process "Zed"
            set frontmost to true
            delay 0.5
            
            -- Look for authorization dialog or button
            -- Try to find and click "Authorize" or "Continue" button
            try
                -- First try: Look for a dialog window
                if exists window "Authorize" then
                    click button "Authorize" of window "Authorize"
                    return "Authorized via dialog"
                end if
                
                -- Second try: Look for authorization button in main window
                set mainWindow to window 1
                if exists button "Authorize" of mainWindow then
                    click button "Authorize" of mainWindow
                    return "Authorized via button"
                end if
                
                -- Third try: Look for "Continue" or "Yes" in any dialog
                repeat with w in windows
                    if exists button "Continue" of w then
                        click button "Continue" of w
                        return "Authorized via Continue button"
                    else if exists button "Yes" of w then
                        click button "Yes" of w
                        return "Authorized via Yes button"
                    else if exists button "Allow" of w then
                        click button "Allow" of w
                        return "Authorized via Allow button"
                    end if
                end repeat
                
                -- Fourth try: Use keyboard shortcut if available
                -- Common authorization shortcuts
                keystroke "y" -- for "yes"
                delay 0.1
                key code 36 -- Enter key
                
            on error errMsg
                display dialog "Could not find authorization button: " & errMsg buttons {"OK"} default button "OK"
            end try
        end tell
    end tell
end run