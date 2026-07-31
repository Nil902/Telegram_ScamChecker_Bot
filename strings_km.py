"""Khmer output strings.

DESIGN: the LLM never generates Khmer. Every user-facing Khmer sentence is
written here by hand and looked up by finding code. This guarantees the
safety-critical text is correct and consistent, costs no API calls, and adds
no latency.

⚠️  REVIEW REQUIRED: every string below must be checked by a native Khmer
speaker before deployment. Run `python review_khmer.py` to print them all
for review. Machine-assisted translation is a starting point, not a
finished product — wrong Khmer in a safety warning is worse than English.
"""

# --- verdict labels -----------------------------------------------------

VERDICT_LABEL = {
    "SAFE":       "🟢 សុវត្ថិភាព",
    "SUSPICIOUS": "🟡 គួរប្រយ័ត្ន",
    "DANGEROUS":  "🔴 គ្រោះថ្នាក់",
}

VERDICT_LABEL_EN = {
    "SAFE":       "SAFE",
    "SUSPICIOUS": "BE CAREFUL",
    "DANGEROUS":  "DANGEROUS",
}

# --- default next step per verdict --------------------------------------

# Wording is neutral between a file and a link, because the bot now checks
# both — "open" covers opening a file and opening a link alike.
NEXT_STEP = {
    "SAFE":       "អ្នកអាចបើកវាបាន។",
    "SUSPICIOUS": "កុំបើកវា បើអ្នកមិនស្គាល់អ្នកផ្ញើច្បាស់លាស់។",
    "DANGEROUS":  "កុំបើក ហើយកុំចុចវា។ សូមលុបវាចោល។",
}

NEXT_STEP_EN = {
    "SAFE":       "You can open this.",
    "SUSPICIOUS": "Do not open this unless you are sure who sent it.",
    "DANGEROUS":  "Do not open or click this. Delete it.",
}

# --- fallback when no finding fired -------------------------------------

NO_DANGER_FOUND = "ខ្ញុំមិនបានរកឃើញអ្វីគ្រោះថ្នាក់ក្នុងឯកសារនេះទេ។"
NO_DANGER_FOUND_EN = "I did not find anything dangerous in this file."

# --- "checked nothing" is not the same as "checked and clean" -----------
# Shown instead of the green SAFE label when the only thing we can say is
# that no rule covers this file type. White, not green: the user must not
# read absence of evidence as evidence of absence.

VERDICT_LABEL_UNVERIFIED = "⚪ មិនអាចផ្ទៀងផ្ទាត់បាន"
VERDICT_LABEL_UNVERIFIED_EN = "NOT FULLY CHECKED"

# Header for the LLM-triage section. Deterministic findings are stated
# flatly; anything under this header is explicitly marked as an unconfirmed
# guess, so the two can never be mistaken for one another in the reply.
LLM_SUGGESTED_HEADER = (
    "🤖 ការសន្និដ្ឋានដោយកុំព្យូទ័រ (មិនទាន់បញ្ជាក់) / Computer guess (unconfirmed):"
)

NEXT_STEP_UNVERIFIED = "បើអ្នកមិនស្គាល់អ្នកផ្ញើច្បាស់លាស់ សូមកុំបើកវា។"
NEXT_STEP_UNVERIFIED_EN = (
    "Open it only if you are sure who sent it and you expected this file."
)

# --- the analysis itself could not run --------------------------------------
# The AI was rate-limited, timed out, or returned nothing. This is NOT a
# judgement about the file — we simply could not check it — so the reply must
# not read as "suspicious". It is still never green: the user is told to wait
# and to not open the file until it has actually been checked.

VERDICT_LABEL_UNAVAILABLE = "⏳ ពិនិត្យមិនទាន់បាន"
VERDICT_LABEL_UNAVAILABLE_EN = "COULD NOT CHECK RIGHT NOW"

SERVICE_UNAVAILABLE = (
    "ខ្ញុំកំពុងជាប់រវល់ ហើយមិនអាចពិនិត្យឯកសារនេះឲ្យចប់បានទេ។ "
    "សូមរង់ចាំមួយភ្លែត រួចផ្ញើវាមកម្ដងទៀត។"
)
SERVICE_UNAVAILABLE_EN = (
    "I am busy right now and could not finish checking this. "
    "Please wait a moment and send it to me again."
)

NEXT_STEP_UNAVAILABLE = "រហូតដល់ពិនិត្យរួច សូមកុំបើកឯកសារនេះ។"
NEXT_STEP_UNAVAILABLE_EN = "Until it has been checked, do not open it."

# --- one Khmer sentence per finding code --------------------------------
# Templates may reference {placeholders} filled from Finding.params.

FINDING_KM: dict[str, str] = {

    # ---- filename rules ----
    "FILENAME_RTL_OVERRIDE":
        "ឈ្មោះឯកសារនេះមានតួអក្សរលាក់ ដែលធ្វើឲ្យអ្នកមើលឃើញប្រភេទឯកសារខុសពីការពិត។",

    "FILENAME_DOUBLE_EXTENSION":
        "ឯកសារនេះមើលទៅដូចជាឯកសារធម្មតា ប៉ុន្តែតាមពិតវាជាកម្មវិធីដែលដំណើរការលើទូរស័ព្ទរបស់អ្នក។",

    # Deliberately generic. This one code covers .apk, .exe, .msi, .ps1 and
    # the rest, so the wording must be true of all of them — an earlier
    # version said "Android app installer" and told users receiving a Windows
    # .msi about Android.
    "FILENAME_EXECUTABLE":
        "ឯកសារនេះជាកម្មវិធីដែលដំណើរការលើឧបករណ៍របស់អ្នក។ ធនាគារ និងក្រុមហ៊ុននៅកម្ពុជាមិនដែលផ្ញើកម្មវិធីតាម Telegram ទេ។",

    "FILENAME_SHORTCUT":
        "ឯកសារនេះជាផ្លូវកាត់។ ពេលអ្នកបើកវា វានឹងដំណើរការកម្មវិធីមួយដែលអ្នកមើលមិនឃើញឈ្មោះ។",

    "FILENAME_SYSTEM_MODIFIER":
        "ឯកសារនេះកែប្រែការកំណត់ខាងក្នុងកុំព្យូទ័រ Windows។ ធនាគារ ឬក្រុមហ៊ុនដឹកជញ្ជូនមិនដែលផ្ញើឯកសារបែបនេះទេ។",

    "FILENAME_DISK_IMAGE":
        "នេះជារូបភាពថាស។ Windows បើកវាដូចជា USB ដែលធ្វើឲ្យអ្វីៗនៅខាងក្នុងរំលងការព្រមានសុវត្ថិភាពធម្មតា។",

    "FILENAME_MACRO_ENABLED":
        "ឯកសារប្រភេទនេះអាចដំណើរការបញ្ជាលាក់កំបាំង នៅពេលអ្នកបើកវា។",

    # ---- virus database ----
    "VT_KNOWN_MALWARE":
        "កម្មវិធីស្កេនមេរោគចំនួន {detections} ក្នុងចំណោម {total} បានស្គាល់ឯកសារនេះថាជាកម្មវិធីព្យាបាទ។ សូមកុំបើកវាឡើយ។",

    "VT_SUSPECTED_MALWARE":
        "កម្មវិធីស្កេនមេរោគចំនួន {detections} ក្នុងចំណោម {total} បានដាស់តឿនអំពីឯកសារនេះ។ ចំនួននេះតិច ដូច្នេះវាអាចជាការភ័ន្តច្រឡំ ប៉ុន្តែសូមប្រុងប្រយ័ត្ន។",

    "VT_SCAN_UNAVAILABLE":
        "ខ្ញុំមិនអាចប្រៀបធៀបឯកសារនេះជាមួយបញ្ជីមេរោគដែលគេស្គាល់បានទេ ដូច្នេះវាមិនទាន់ត្រូវបានពិនិត្យពេញលេញឡើយ។",

    # ---- LLM triage (unrecognised file types only; capped at MEDIUM) ----
    # These are guesses, and the wording says so in every case. They are
    # rendered under a separate header so a user can tell at a glance that
    # this line is weaker evidence than the rest.
    "LLM_SUGGESTED_INSTALLER":
        "ឯកសារនេះមើលទៅដូចជាអាចដំឡើងកម្មវិធីលើឧបករណ៍របស់អ្នក ប៉ុន្តែខ្ញុំមិនអាចបញ្ជាក់ច្បាស់បានទេ។",

    "LLM_SUGGESTED_SCRIPT":
        "ឯកសារនេះហាក់ដូចជាមានបញ្ជាដែលកុំព្យូទ័រនឹងដំណើរការ ប៉ុន្តែខ្ញុំមិនអាចបញ្ជាក់ច្បាស់បានទេ។",

    "LLM_SUGGESTED_CREDENTIAL_PROMPT":
        "ឯកសារនេះនិយាយអំពីពាក្យសម្ងាត់ ឬការចូលគណនីធនាគារ ដែលមិនធម្មតាសម្រាប់ឯកសារផ្ញើតាម Telegram។",

    "LLM_SUGGESTED_OBFUSCATED":
        "មាតិកាឯកសារនេះមើលទៅដូចជាត្រូវបានធ្វើឲ្យច្របូកច្របល់ដោយចេតនា ដើម្បីលាក់អ្វីដែលវាធ្វើ។",

    "LLM_SUGGESTED_NETWORK_BEACON":
        "ឯកសារនេះមានអាសយដ្ឋានគេហទំព័រ ដែលវាអាចទាក់ទងដោយខ្លួនឯង។",

    # ---- coverage ----
    "UNKNOWN_FILE_TYPE":
        "ខ្ញុំមិនបានឃើញសញ្ញាគ្រោះថ្នាក់ក្នុងឯកសារនេះទេ ប៉ុន្តែខ្ញុំមិនអាចពិនិត្យឯកសារប្រភេទនេះបានពេញលេញឡើយ។ សូមចាត់ទុកវាថាមិនទាន់ផ្ទៀងផ្ទាត់ មិនមែនថាមានសុវត្ថិភាពទេ។",

    "ARCHIVE_PASSWORD_IN_MESSAGE":
        "ឯកសារនេះត្រូវបានចាក់សោដោយពាក្យសម្ងាត់ក្នុងសារ។ គេធ្វើដូច្នេះដើម្បីលាក់មាតិកាពីកម្មវិធីការពារ មិនមែនដើម្បីការពារអ្នកទេ។",

    # ---- file type ----
    "TYPE_DISGUISED_EXECUTABLE":
        "ឯកសារនេះមានឈ្មោះដូចជាឯកសារធម្មតា ប៉ុន្តែតាមពិតវាជាកម្មវិធីដែលដំណើរការលើឧបករណ៍របស់អ្នក។",

    "TYPE_MISMATCH":
        "ឈ្មោះឯកសារនិងមាតិកាពិតរបស់វាមិនដូចគ្នាទេ។",

    "TYPE_HIDDEN_APK":
        "នេះជាកម្មវិធីដំឡើង Android ដែលត្រូវបានលាក់ដោយប្តូរឈ្មោះឯកសារ។",

    # ---- APK: dangerous combinations ----
    "APK_OTP_THEFT_SIGNATURE":
        "កម្មវិធីនេះអាចមើលអេក្រង់របស់អ្នក និងអានលេខកូដដែលធនាគារផ្ញើមក។ នេះជារបៀបដែលគេលួចលុយពីគណនីរបស់អ្នក។",

    "APK_OVERLAY_ATTACK_SIGNATURE":
        "កម្មវិធីនេះអាចបង្ហាញអេក្រង់ក្លែងក្លាយពីលើកម្មវិធីធនាគារពិតរបស់អ្នក។",

    "APK_REMOTE_ACCESS_TOOL":
        "{name} ជាកម្មវិធីពិត មិនមែនក្លែងក្លាយទេ។ ប៉ុន្តែវាអនុញ្ញាតឲ្យអ្នកដទៃមើល និងបញ្ជាទូរស័ព្ទរបស់អ្នកពីចម្ងាយ។ "
        "បើមានអ្នកណាប្រាប់ឲ្យអ្នកដំឡើងវា ជាពិសេសអ្នកដែលអះអាងថាមកពីធនាគារ នគរបាល ឬរដ្ឋាភិបាល នោះជាការបោកប្រាស់។ "
        "ធនាគារ និងរដ្ឋាភិបាលមិនដែលសុំឲ្យអ្នកដំឡើងកម្មវិធីនេះទេ។",

    # ---- APK: impersonation ----
    "APK_CLAIMS_REAL_PACKAGE":
        "កម្មវិធីនេះប្រើឈ្មោះផ្លូវការរបស់ {bank} ប៉ុន្តែកម្មវិធីធនាគារពិតមានតែនៅក្នុង Play Store ប៉ុណ្ណោះ មិនមែននៅក្នុង Telegram ទេ។",

    "APK_PACKAGE_TYPOSQUAT":
        "ឈ្មោះខាងក្នុងរបស់កម្មវិធីនេះស្រដៀងនឹងកម្មវិធីពិតរបស់ {bank} ណាស់ ប៉ុន្តែមិនដូចគ្នាទេ។ វាជាកម្មវិធីក្លែងក្លាយ។",

    "APK_BRAND_IMPERSONATION":
        "កម្មវិធីនេះប្រើឈ្មោះ '{brand}' ប៉ុន្តែវាមិនមែនជាកម្មវិធីផ្លូវការរបស់ក្រុមហ៊ុននោះទេ។",

    # ---- APK: individual permissions ----
    "APK_PERMISSION_BIND_ACCESSIBILITY_SERVICE":
        "កម្មវិធីនេះអាចមើលឃើញអ្វីៗទាំងអស់នៅលើអេក្រង់របស់អ្នក និងចុចប៊ូតុងជំនួសអ្នក។",

    "APK_PERMISSION_RECEIVE_SMS":
        "កម្មវិធីនេះអាចអានសារ SMS ដែលអ្នកទទួល រួមទាំងលេខកូដពីធនាគារ។",

    "APK_PERMISSION_READ_SMS":
        "កម្មវិធីនេះអាចអានសារ SMS ដែលរក្សាទុកក្នុងទូរស័ព្ទរបស់អ្នក។",

    "APK_PERMISSION_SYSTEM_ALERT_WINDOW":
        "កម្មវិធីនេះអាចបង្ហាញអេក្រង់ក្លែងក្លាយពីលើកម្មវិធីផ្សេងទៀត។",

    "APK_PERMISSION_REQUEST_INSTALL_PACKAGES":
        "កម្មវិធីនេះអាចដំឡើងកម្មវិធីផ្សេងទៀតទៅក្នុងទូរស័ព្ទរបស់អ្នក។",

    "APK_PERMISSION_BIND_DEVICE_ADMIN":
        "កម្មវិធីនេះអាចរារាំងអ្នកមិនឲ្យលុបវាចេញបាន។",

    "APK_PERMISSION_SEND_SMS":
        "កម្មវិធីនេះអាចផ្ញើសារ SMS ដែលអ្នកនឹងត្រូវបង់ប្រាក់។",

    "APK_PERMISSION_READ_CONTACTS":
        "កម្មវិធីនេះអាចអានបញ្ជីទំនាក់ទំនងរបស់អ្នក។",

    "APK_PERMISSION_CALL_PHONE":
        "កម្មវិធីនេះអាចហៅទូរស័ព្ទដោយមិនសួរអ្នក។",

    # ---- APK: other ----
    "APK_OLD_TARGET_SDK":
        "កម្មវិធីនេះត្រូវបានសាងសង់សម្រាប់ Android ជំនាន់ចាស់ ដើម្បីគេចពីការការពារសុវត្ថិភាពថ្មីៗ។",

    "APK_PARSE_FAILED":
        "ឯកសារនេះមិនអាចអានជាកម្មវិធី Android ធម្មតាបានទេ ដែលជាការមិនប្រក្រតី។",

    # ---- analysis could not complete ----
    "ANALYSIS_FAILED":
        "ខ្ញុំមិនអាចពិនិត្យឯកសារនេះបានពេញលេញទេ។ ដោយសារខ្ញុំមិនអាចពិនិត្យបាន សូមកុំបើកវា លុះត្រាតែអ្នកស្គាល់អ្នកផ្ញើច្បាស់លាស់។",

    # ---- web links ----
    "LINK_IP_ADDRESS":
        "តំណនេះនាំទៅកាន់អាសយដ្ឋានជាលេខ មិនមែនឈ្មោះគេហទំព័រពិតទេ។ ធនាគារ និងក្រុមហ៊ុនពិតមិនដែលផ្ញើតំណបែបនេះទេ។",

    "LINK_AT_OBFUSCATION":
        "តំណនេះត្រូវបានរៀបចំដើម្បីបោកអ្នក។ វាមើលទៅដូចជាគេហទំព័រមួយ ប៉ុន្តែតាមពិតវាបើក '{host}'។",

    "LINK_PUNYCODE":
        "តំណនេះប្រើអក្សរលាក់កំបាំង ដើម្បីឲ្យមើលទៅដូចជាគេហទំព័រពិត ប៉ុន្តែតាមពិតវាជាច្បាប់ចម្លងក្លែងក្លាយ។",

    "LINK_BRAND_IMPERSONATION":
        "តំណនេះប្រើឈ្មោះ '{brand}' ប៉ុន្តែគេហទំព័រ '{host}' មិនមែនជាគេហទំព័រផ្លូវការរបស់ '{brand}' ទេ។ វាជាការក្លែងបន្លំ។",

    "LINK_SHORTENER":
        "តំណនេះលាក់កន្លែងដែលវានាំទៅ។ អ្នកមិនអាចដឹងគេហទំព័រពិតបានទេ រហូតដល់អ្នកបានចុចវារួច។",

    "LINK_SUSPICIOUS_TLD":
        "តំណនេះប្រើកន្ទុយអាសយដ្ឋានគេហទំព័រ ដែលគេប្រើញឹកញាប់សម្រាប់ការបោកប្រាស់។",

    "LINK_REWARD_LURE":
        "សារនេះផ្តល់ជូនលុយងាយៗ រង្វាន់ ឬការងារក្រៅម៉ោងដែលទទួលបានប្រាក់ច្រើនតែធ្វើការតិច ហើយបង្ខំឲ្យអ្នកចុចតំណ។ ការផ្តល់ជូនបែបនេះ ដូចជាការងារ 'Order grabbing' ឬចំណូលប្រចាំថ្ងៃធានា គឺជាល្បិចបោកប្រាស់។ សូមកុំចុចតំណ ឬបង់ប្រាក់ណាមួយឡើយ។",
}


# --- next-move prediction per finding code ------------------------------
#
# Detection warns a user once. Telling them what the scammer will do NEXT
# protects them on every future contact. These are shown between the reason
# and the next-step in the reply card, ONLY when the highest-severity finding
# has an entry here. Keys are real finding codes emitted by the detection
# layer — never invent a prediction for a code that cannot fire.
#
# ⚠️ REVIEW REQUIRED: like every Khmer string here, these await native-speaker
# review before deployment. Run `python review_khmer.py`.

NEXT_MOVE_KM: dict[str, str] = {
    "LINK_BRAND_IMPERSONATION":
        "ទំព័រក្លែងក្លាយនឹងសុំឈ្មោះ និងពាក្យសម្ងាត់ចូលគណនីរបស់អ្នក បន្ទាប់មកសុំលេខកូដដែលផ្ញើមកទូរស័ព្ទរបស់អ្នក។ លេខកូដនោះនឹងផ្ទេរលុយចេញ។",
    "LINK_PUNYCODE":
        "ទំព័រក្លែងក្លាយនឹងសុំឈ្មោះ និងពាក្យសម្ងាត់ចូលគណនីរបស់អ្នក បន្ទាប់មកសុំលេខកូដពីទូរស័ព្ទរបស់អ្នក។",
    "LINK_REWARD_LURE":
        "ដំបូងគេអាចផ្ញើលុយតិចតួចមកអ្នក ដើម្បីឲ្យអ្នកទុកចិត្ត បន្ទាប់មកគេនឹងសុំឲ្យអ្នកដាក់ប្រាក់កក់មុន។",
    "LINK_SHORTENER":
        "តំណខ្លីនេះនឹងនាំអ្នកទៅទំព័រចូលគណនីក្លែងក្លាយ ឬឲ្យអ្នកដំឡើងកម្មវិធីមួយ។",
    "LINK_IP_ADDRESS":
        "ទំព័រនេះនឹងសុំព័ត៌មានផ្ទាល់ខ្លួន ឬលុយ។ សូមកុំបញ្ចូលអ្វីទាំងអស់។",
    "APK_OTP_THEFT_SIGNATURE":
        "គេនឹងប្រាប់ឲ្យអ្នកអនុញ្ញាតការដំឡើងពីប្រភពមិនស្គាល់ បន្ទាប់មកបើកមុខងារ Accessibility។ សូមកុំធ្វើតាម។",
    "APK_OVERLAY_ATTACK_SIGNATURE":
        "កម្មវិធីនឹងបង្ហាញអេក្រង់ក្លែងក្លាយពីលើកម្មវិធីធនាគាររបស់អ្នក ដើម្បីលួចយកពាក្យសម្ងាត់។",
    "APK_REMOTE_ACCESS_TOOL":
        "គេនឹងសុំឲ្យអ្នកអានលេខ ៩ ខ្ទង់ (លេខភ្ជាប់) ឲ្យគេ បន្ទាប់មកគេនឹងមើលអេក្រង់របស់អ្នក។",
    "FILENAME_EXECUTABLE":
        "គេនឹងប្រាប់ថាការដំឡើងបរាជ័យ ហើយផ្ញើឯកសារមួយទៀតឲ្យអ្នកសាកម្តងទៀត។",
    "FILENAME_DOUBLE_EXTENSION":
        "គេនឹងប្រាប់ថាឯកសារមិនបើក ហើយផ្ញើឯកសារមួយទៀតឲ្យអ្នកសាកម្តងទៀត។",
    "TYPE_HIDDEN_APK":
        "ពេលអ្នកបើកវា គេនឹងណែនាំឲ្យអ្នកអនុញ្ញាតការដំឡើង និងបើកសិទ្ធិផ្សេងៗ។",
    "TYPE_DISGUISED_EXECUTABLE":
        "ពេលអ្នកបើកវា វានឹងព្យាយាមដំឡើងកម្មវិធីលើឧបករណ៍របស់អ្នក។",
    "ARCHIVE_PASSWORD_IN_MESSAGE":
        "គេឲ្យពាក្យសម្ងាត់ ដើម្បីឲ្យអ្នកបើកឯកសារ ដែលកម្មវិធីការពារមើលមិនឃើញខាងក្នុង។",
}

NEXT_MOVE_EN: dict[str, str] = {
    "LINK_BRAND_IMPERSONATION":
        "The fake page will ask for your login, then for the code sent to your "
        "phone. That code is what moves the money out.",
    "LINK_PUNYCODE":
        "The lookalike page will ask for your account login and password, then "
        "the code from your phone.",
    "LINK_REWARD_LURE":
        "They will pay you a small amount first to build trust, then ask you to "
        "deposit money.",
    "LINK_SHORTENER":
        "This short link will take you to a fake login page or ask you to "
        "install an app.",
    "LINK_IP_ADDRESS":
        "This page will ask for personal details or money. Do not enter "
        "anything.",
    "APK_OTP_THEFT_SIGNATURE":
        "They will tell you to allow installs from unknown sources, then to "
        "turn on the accessibility permission. Do not do it.",
    "APK_OVERLAY_ATTACK_SIGNATURE":
        "The app will show a fake screen over your bank app to steal your "
        "password.",
    "APK_REMOTE_ACCESS_TOOL":
        "They will ask you to read out a 9-digit connection number, then they "
        "will watch your screen.",
    "FILENAME_EXECUTABLE":
        "They will tell you the install failed and send you another file to "
        "try again.",
    "FILENAME_DOUBLE_EXTENSION":
        "They will say the file did not open and send you another file to try.",
    "TYPE_HIDDEN_APK":
        "When you open it, they will guide you to allow the install and grant "
        "permissions.",
    "TYPE_DISGUISED_EXECUTABLE":
        "When you open it, it will try to install a program on your device.",
    "ARCHIVE_PASSWORD_IN_MESSAGE":
        "They give you the password so you open the file that security scanners "
        "could not see inside.",
}