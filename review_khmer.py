"""Print every Khmer string with its English source, for native-speaker review.

Run:  python review_khmer.py > khmer_review.txt
Then have a Khmer speaker read it and mark anything wrong or unnatural.
"""
import strings_km as km

ENGLISH_SOURCE = {
    "FILENAME_RTL_OVERRIDE":
        "The filename contains a hidden character that disguises the real file type.",
    "FILENAME_DOUBLE_EXTENSION":
        "The file looks like a document but is really a program.",
    "FILENAME_EXECUTABLE":
        "This file is a program that runs on your device. Banks and companies in Cambodia never send programs through Telegram.",
    "FILENAME_SHORTCUT":
        "This file is a shortcut. Opening it silently starts a program you cannot see the name of.",
    "FILENAME_SYSTEM_MODIFIER":
        "This file changes settings deep inside a Windows computer. It is not something a bank or a delivery company would ever send you.",
    "FILENAME_DISK_IMAGE":
        "This is a disk image. Windows opens it like a USB stick, which lets whatever is inside skip the usual safety warning.",
    "FILENAME_MACRO_ENABLED":
        "This document can run hidden commands when opened.",
    "ARCHIVE_PASSWORD_IN_MESSAGE":
        "The file is locked with a password from the message. This hides the contents from security scanners.",
    "VT_KNOWN_MALWARE":
        "{detections} of {total} virus scanners recognise this exact file as harmful software.",
    "VT_SUSPECTED_MALWARE":
        "{detections} of {total} virus scanners flagged this file. That is a small number, so it may be "
        "a false alarm, but be careful.",
    "VT_SCAN_UNAVAILABLE":
        "I could not compare this file against the database of known viruses, so it has not been fully checked.",
    "UNKNOWN_FILE_TYPE":
        "I found no known danger sign in this file, but I do not have a way to fully check this type of file. "
        "Treat it as unverified rather than confirmed safe.",
    "TYPE_DISGUISED_EXECUTABLE":
        "This file is named like a document, but it is actually a program that runs on your device.",
    "TYPE_MISMATCH":
        "The file's name and its real contents do not match.",
    "TYPE_HIDDEN_APK":
        "This is an Android app installer disguised with a different file name.",
    "APK_OTP_THEFT_SIGNATURE":
        "This app can watch your screen and capture the code your bank sends. That is how money is stolen.",
    "APK_OVERLAY_ATTACK_SIGNATURE":
        "This app can show a fake screen over your real bank app.",
    "APK_REMOTE_ACCESS_TOOL":
        "{name} is a real app, not a fake. But it lets another person see and control your phone from anywhere. "
        "If someone asked you to install it, especially someone claiming to be from your bank, the police, or a "
        "government office, this is a scam. Banks and government offices never ask you to install this.",
    "APK_CLAIMS_REAL_PACKAGE":
        "This app uses the official name of {bank}, but genuine bank apps are only in the Play Store, never Telegram.",
    "APK_PACKAGE_TYPOSQUAT":
        "The app's internal name is almost identical to {bank}'s real app, but not the same. It is an imitation.",
    "APK_BRAND_IMPERSONATION":
        "This app uses the name '{brand}' but is not the official app from that company.",
    "APK_PERMISSION_BIND_ACCESSIBILITY_SERVICE":
        "This app can see everything on your screen and tap buttons for you.",
    "APK_PERMISSION_RECEIVE_SMS":
        "This app can read the SMS messages you receive, including bank codes.",
    "APK_PERMISSION_READ_SMS":
        "This app can read the SMS messages saved on your phone.",
    "APK_PERMISSION_SYSTEM_ALERT_WINDOW":
        "This app can draw fake screens on top of your other apps.",
    "APK_PERMISSION_REQUEST_INSTALL_PACKAGES":
        "This app can install more apps onto your phone.",
    "APK_PERMISSION_BIND_DEVICE_ADMIN":
        "This app can stop you from uninstalling it.",
    "APK_PERMISSION_SEND_SMS":
        "This app can send SMS messages that you will be charged for.",
    "APK_PERMISSION_READ_CONTACTS":
        "This app can read your contact list.",
    "APK_PERMISSION_CALL_PHONE":
        "This app can make phone calls without asking you.",
    "APK_OLD_TARGET_SDK":
        "This app is built for an old version of Android so it can avoid newer security protections.",
    "APK_PARSE_FAILED":
        "This file could not be read as a normal Android app, which is itself unusual.",
    "ANALYSIS_FAILED":
        "I could not finish checking this file. Because I could not check it, "
        "please do not open it unless you are certain who sent it.",
    "LINK_IP_ADDRESS":
        "This link goes to a numbered address instead of a real website name. "
        "Real banks and companies never send links like this.",
    "LINK_AT_OBFUSCATION":
        "This link is built to trick you. It looks like one website but "
        "actually opens '{host}'.",
    "LINK_PUNYCODE":
        "This link uses hidden letters to look like a real website while "
        "actually being a fake copy.",
    "LINK_BRAND_IMPERSONATION":
        "This link uses the name '{brand}', but the website '{host}' is not "
        "the official '{brand}' website. It is an imitation.",
    "LINK_SHORTENER":
        "This link hides where it really goes. You cannot see the real website "
        "until after you have opened it.",
    "LINK_SUSPICIOUS_TLD":
        "This link uses a web-address ending that is very often used for scams.",
    "LINK_REWARD_LURE":
        "This message offers easy money, a prize, or a part-time job that pays "
        "a lot for little work, and pushes you to click a link. Offers like "
        "'order grabbing' jobs or guaranteed daily income are a common scam. "
        "Do not click the link or pay any money.",
}


def main():
    print("=" * 70)
    print("KHMER STRING REVIEW")
    print("Please mark any sentence that is wrong, unclear, or unnatural.")
    print("The reader is an ordinary person with no computer training.")
    print("=" * 70)

    print("\n--- VERDICT LABELS ---\n")
    for key, text in km.VERDICT_LABEL.items():
        print(f"  {key:<12} {text}")

    print("\n--- NEXT STEPS ---\n")
    for key in km.NEXT_STEP:
        print(f"  {key}")
        print(f"    EN: {km.NEXT_STEP_EN[key]}")
        print(f"    KM: {km.NEXT_STEP[key]}\n")

    print("--- FINDING EXPLANATIONS ---\n")
    for code, khmer in km.FINDING_KM.items():
        print(f"  [{code}]")
        print(f"    EN: {ENGLISH_SOURCE.get(code, '(no English source recorded)')}")
        print(f"    KM: {khmer}")
        print()

    missing = set(ENGLISH_SOURCE) - set(km.FINDING_KM)
    if missing:
        print("!! MISSING KHMER TRANSLATIONS:")
        for code in sorted(missing):
            print(f"   {code}")

    print(f"\nTotal strings to review: "
          f"{len(km.FINDING_KM) + len(km.NEXT_STEP) + len(km.VERDICT_LABEL)}")


if __name__ == "__main__":
    main()