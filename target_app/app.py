"""target_app: the deliberately vulnerable site (the vulnerable zone). It's a
separate Flask app and database from breachbox_app. Vulnerabilities: SQLi
(/login), XSS (/feedback), IDOR (/tickets/<id>), command injection
(/diagnostics), path traversal (/reports) and a chained IDOR to staff
console (/staff/console)."""

import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_APP_DIR, "target_app.db")
_OPS_NOTES_PATH = os.path.join(_APP_DIR, "ops_notes.txt")
_REPORTS_DIR = os.path.join(_APP_DIR, "reports")
_STAFF_REPORT_FLAG_PATH = os.path.join(_APP_DIR, "staff_only_report.txt")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", f"sqlite:///{_DB_PATH}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Plaintext flags. breachbox only ever stores the hash of each.
SQLI_FLAG = "flag{sql1_st4ff_p0rt4l_byp4ss_2026}"
XSS_FLAG = "flag{r3fl3ct3d_xss_st4ff_f33db4ck_2026}"
IDOR_FLAG = "flag{1d0r_t1ck3t_3num3r4t10n_2026}"
CMDI_FLAG = "flag{cmd1_p1ng_ut1l1ty_1nj3ct10n_2026}"
PTRAVERSAL_FLAG = "flag{p4th_tr4v3rs4l_r3p0rt_v13w3r_2026}"
CHAINED_FLAG = "flag{ch41n3d_1d0r_t0_st4ff_c0ns0l3_2026}"

# Leaked on purpose inside a staff ticket, which is the chained challenge:
# read the ticket through the IDOR, then reuse the token at /staff/console.
STAFF_CONSOLE_TOKEN = "s3ss-9f2a7c41-staff-console"


class StaffUser(db.Model):
    __tablename__ = "staff_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class Ticket(db.Model):
    __tablename__ = "tickets"

    id = db.Column(db.Integer, primary_key=True)
    requester_name = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)


def seed_dummy_staff_accounts():
    if StaffUser.query.count() == 0:
        db.session.add_all([
            StaffUser(username="admin", password="staffportal2026"),
            StaffUser(username="itsupport", password="hunter2"),
        ])
        db.session.commit()


def seed_admin_ticket():
    if Ticket.query.count() == 0:
        db.session.add(Ticket(
            requester_name="admin",
            subject="Password rotation reminder",
            body=(
                "Internal note, staff eyes only: rotate the staff portal "
                "credentials after last week's incident review. "
                f"Flag: {IDOR_FLAG}"
            ),
        ))
        db.session.commit()


def seed_ops_notes_file():
    if not os.path.exists(_OPS_NOTES_PATH):
        with open(_OPS_NOTES_PATH, "w") as f:
            f.write(
                "Internal ops notes, not linked from the site anywhere.\n"
                f"Flag: {CMDI_FLAG}\n"
            )


def seed_reports():
    # The real flag file is written one level above _REPORTS_DIR, so it's only
    # reachable from the viewer by escaping the folder with ../.
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    seed_files = {
        "weekly_summary.txt": "Weekly staff summary: nothing unusual to report.\nØˆ°(€€€€€€€€‰¥¹¥‘•¹Ñ}±½œ¹ÑáĞˆè€‰%¹¥‘•¹Ğ±½œè€À½Á•¸¥¹¥‘•¹ÑÌÑ¡¥Ìİ••¬¹q¸ˆ°(€€€ô(€€€™½È™¥±•¹…µ”°½¹Ñ•¹ÑÌ¥¸Í••‘}™¥±•Ì¹¥Ñ•µÌ ¤è(€€€€€€€Á…Ñ €ô½Ì¹Á…Ñ ¹©½¥¸¡}IA=IQM}%H°™¥±•¹…µ”¤(€€€€€€€¥˜¹½Ğ½Ì¹Á…Ñ ¹•á¥ÍÑÌ¡Á…Ñ ¤è(€€€€€€€€€€€İ¥Ñ ½Á•¸¡Á…Ñ °€‰Üˆ¤…Ì˜è(€€€€€€€€€€€€€€€˜¹İÉ¥Ñ”¡½¹Ñ•¹ÑÌ¤(€€€¥˜¹½Ğ½Ì¹Á…Ñ ¹•á¥ÍÑÌ¡}MQ}IA=IQ}1}AQ ¤è(€€€€€€€İ¥Ñ ½Á•¸¡}MQ}IA=IQ}1}AQ °€‰Üˆ¤…Ì˜è(€€€€€€€€€€€˜¹İÉ¥Ñ” (€€€€€€€€€€€€€€€€‰MÑ…™˜µ½¹±äÉ•Á½ÉĞ°¹½Ğµ•…¹ĞÑ¼‰”Í•ÉÙ•‰äÑ¡”Ù¥•İ•È¹q¸ˆ(€€€€€€€€€€€€€€€˜‰±…œèíAQIYIM1}1õq¸ˆ(€€€€€€€€€€€€¤(()‘•˜Í••‘}ÍÑ…™™}½¹Í½±•}Ñ¥­•Ğ ¤è(€€€€ŒAÕÑÌÑ¡”ÍÑ…™˜µ½¹Í½±”Ñ½­•¸¥¸„Ñ¥­•ĞÑ¡…Ğ¥Í¸ĞÑ¡”Ù¥•İ•ÈÌ½İ¸°(€€€€ŒÍ¼¥ĞÌÉ•…¡…‰±”Ñ¡É½Õ Ñ¡”Ñ¥­•Ğ%=H€¡ÍÑ•À½¹”½˜Ñ¡”¡…¥¸¤¸(€€€•á¥ÍÑ¥¹œ€ôQ¥­•Ğ¹ÅÕ•Éä¹™¥±Ñ•É}‰ä¡ÍÕ‰©•Ğô‰MÑ…™˜½¹Í½±”…•ÍÌˆ¤¹™¥ÉÍĞ ¤(€€€¥˜•á¥ÍÑ¥¹œ¥Ì9½¹”è(€€€€€€€‘ˆ¹Í•ÍÍ¥½¸¹…‘¡Q¥­•Ğ (€€€€€€€€€€€É•ÅÕ•ÍÑ•É}¹…µ”ô‰¥ÑÍÕÁÁ½ÉĞˆ°(€€€€€€€€€€€ÍÕ‰©•Ğô‰MÑ…™˜½¹Í½±”…•ÍÌˆ°(€€€€€€€€€€€‰½‘äô (€€€€€€€€€€€€€€€€‰I•µ¥¹‘•È™½ÈÍÑ…™˜èÑ¡”¥¹Ñ•É¹…°½¹Í½±”Í•ÍÍ¥½¸Ñ½­•¸¥Ì€ˆ(€€€€€€€€€€€€€€€˜‰íMQ}=9M=1}Q=-9ô¸¼¹½ĞÍ¡…É”¥Ğ½ÕÑÍ¥‘”Ñ¡”Ñ•…´¸ˆ(€€€€€€€€€€€€¤°(€€€€€€€€¤¤(€€€€€€€‘ˆ¹Í•ÍÍ¥½¸¹½µµ¥Ğ ¤(()…ÁÀ¹É½ÕÑ” ˆ¼ˆ¤)‘•˜¥¹‘•à ¤è(€€€É•ÑÕÉ¸É•¹‘•É}Ñ•µÁ±…Ñ” ‰¡½µ”¹¡Ñµ°ˆ¤(()…ÁÀ¹É½ÕÑ” ˆ½±½¥¸ˆ°µ•Ñ¡½‘Ìõl‰P‰t¤)‘•˜±½¥¹}™½É´ ¤è(€€€É•ÑÕÉ¸É•¹‘•É}Ñ•µÁ±…Ñ” ‰±½¥¸¹¡Ñµ°ˆ¤(()…ÁÀ¹É½ÕÑ” ˆ½±½¥¸ˆ°µ•Ñ¡½‘Ìõl‰A=MP‰t¤)‘•˜±½¥¹}ÍÕ‰µ¥Ğ ¤è(€€€ÕÍ•É¹…µ”€ôÉ•ÅÕ•ÍĞ¹™½É´¹•Ğ ‰ÕÍ•É¹…µ”ˆ°€ˆˆ¤(€€€Á…ÍÍİ½É€ôÉ•ÅÕ•ÍĞ¹™½É´¹•Ğ ‰Á…ÍÍİ½Éˆ°€ˆˆ¤((€€€€ŒÙÕ±¹•É…‰±”èÉ…Ü˜µÍÑÉ¥¹œME0°Í¼„ÅÕ½Ñ”±¥­”…‘µ¥¸œ=H€œÄœôœÄ‰É•…­Ì½ÕĞ¸(€€€ÅÕ•Éä€ô€ (€€€€€€€˜‰M1P€¨I=4ÍÑ…™™}ÕÍ•ÉÌ]!IÕÍ•É¹…µ”€ô€íÕÍ•É¹…µ•ôœ€ˆ(€€€€€€€˜‰9Á…ÍÍİ½É€ô€íÁ…ÍÍİ½É‘ôœˆ(€€€€¤(€€€É•ÍÕ±Ğ€ô‘ˆ¹Í•ÍÍ¥½¸¹•á•ÕÑ”¡Ñ•áĞ¡ÅÕ•Éä¤¤¹™•Ñ¡½¹” ¤((€€€¥˜É•ÍÕ±Ğè(€€€€€€€É•ÑÕÉ¸€ (€€€€€€€€€€€˜‰]•±½µ”°íÉ•ÍÕ±Ğ¹ÕÍ•É¹…µ•ô„€ˆ(€€€€€€€€€€€˜‰±…œèíME1%}1ô€ˆ(€€€€€€€€€€€€ˆ¡ÍÕ‰µ¥ĞÑ¡¥Ì™±…œ…Ğ‰É•…¡‰½á}…ÁÀÌ€½…Á¤½ÍÕ‰µ¥Ğ¤ˆ(€€€€€€€€¤((€€€É•ÑÕÉ¸É•¹‘•É}Ñ•µÁ±…Ñ” ‰±½¥¸¹¡Ñµ°ˆ°•ÉÉ½Èô‰%¹Ù…±¥ÕÍ•É¹…µ”½ÈÁ…ÍÍİ½Éˆ¤°€ĞÀÄ(()…ÁÀ¹É½ÕÑ” ˆ½™••‘‰…¬ˆ°µ•Ñ¡½‘Ìõl‰P‰t¤)‘•˜™••‘‰…¬ ¤è(€€€µ•ÍÍ…”€ôÉ•ÅÕ•ÍĞ¹…ÉÌ¹•Ğ ‰µ•ÍÍ…”ˆ°€ˆˆ¤(€€€™±…œ€ôaMM}1¥˜}±½½­Í}±¥­•}İ½É­¥¹}áÍÍ}Á…å±½…¡µ•ÍÍ…”¤•±Í”ƒNone
    return render_template("feedback.html", message=message, flag=flag)


def _looks_like_workin×ŞÜ×Ü^[ØY
Y\ÜØYÙNˆİŠHOˆ›ÛÛ‚ˆÈİ[™È[ˆ›Üˆ™X[œ›İÜÙ\ˆ^Xİ][ÛÈHXİX[YÈ\ÈHØY™Hš[\‚ˆÈ[ˆ™YY˜XÚËš[‚ˆİÙ\™YHY\ÜØYÙK›İÙ\Š
Bˆ™]\›ˆØÜš\ˆ[ˆİÙ\™YÜˆ›Û™\œ›ÜHˆ[ˆİÙ\™YÜˆ›Û›ØYHˆ[ˆİÙ\™Y‚‚\œ›İ]J‹İXÚÙ]ËÛ™]È‹Y]ÙÏVÈ‘ÑU—JB™Yˆ™]×İXÚÙ]Ù›Ü›J
N‚ˆ™]\›ˆ™[™\—İ[\]J›™]×İXÚÙ]š[ŠB‚‚\œ›İ]J‹İXÚÙ]È‹Y]ÙÏVÈ”ÔÕ—JB™YˆÜ™X]WİXÚÙ]

N‚ˆ™\]Y\İ\—Û˜[YHH™\]Y\İ™›Ü›K™Ù]
œ™\]Y\İ\—Û˜[YH‹ˆŠKœİš\

HÜˆ˜[›Û[[İ\È‚ˆİXš™XİH™\]Y\İ™›Ü›K™Ù]
œİXš™Xİ‹ˆŠKœİš\

Bˆ›ÙHH™\]Y\İ™›Ü›K™Ù]
˜›ÙH‹ˆŠKœİš\

BˆXÚÙ]HXÚÙ]
™\]Y\İ\—Û˜[YO\™\]Y\İ\—Û˜[YKİXš™Xİ\İXš™Xİ›ÙOX›ÙJBˆ‹œÙ\ÜÚ[Û‹˜Y
XÚÙ]
Bˆ‹œÙ\ÜÚ[Û‹˜ÛÛ[Z]

Bˆ™]\›ˆ™Y\™Xİ
\›Ù›ÜŠšY]×İXÚÙ]‹XÚÙ]ÚY]XÚÙ]šY
JB‚‚\œ›İ]J‹İXÚÙ]ËÏ[XÚÙ]ÚYˆ‹Y]ÙÏVÈ‘ÑU—JB™YˆšY]×İXÚÙ]
XÚÙ]ÚY
N‚ˆÈ[™\˜X›Nˆ›ÈİÛ™\œÚ\ÚXÚËÛÈ[H˜[YY™]\›œÈ]XÚÙ]‚ˆXÚÙ]H‹œÙ\ÜÚ[Û‹™Ù]
XÚÙ]XÚÙ]ÚY
BˆYˆXÚÙ]\È›Û™N‚ˆ™]\›ˆ“›ÈİXÚXÚÙ]‹ˆ™]\›ˆ™[™\—İ[\]JšY]×İXÚÙ]š[‹XÚÙ]]XÚÙ]
B‚‚\œ›İ]J‹ÙXYÛ›ÜİXÜÈ‹Y]ÙÏVÈ‘ÑU—JB™YˆXYÛ›ÜİXÜ×Ù›Ü›J
N‚ˆ™]\›ˆ™[™\—İ[\]J™XYÛ›ÜİXÜËš[‹İ]]S›Û™JB‚‚\œ›İ]J‹ÙXYÛ›ÜİXÜÈ‹Y]ÙÏVÈ”ÔÕ—JB™YˆXYÛ›ÜİXÜ×Ü[Š
N‚ˆÜİH™\]Y\İ™›Ü›K™Ù]
šÜİ‹ˆŠBˆN‚ˆÈ[™\˜X›NˆÚ[UYHÚ]˜]È[œ]ÛÈÈÜˆ	‰ˆÚZ[œÈHÙXÛÛ™ÛÛ[X[™‚ˆ™\İ[HİXœ›ØÙ\ÜËœ[Šˆˆœ[™ÈXÈHÚÜİH‹ˆÚ[UYKˆØ\\™WÛİ]]UYKˆ^UYKˆ[Y[İ]MKˆ
Bˆİ]]H™\İ[œİİ]
È™\İ[œİ\œ‚ˆ^Ù\İXœ›ØÙ\ÜË•[Y[İ]^\™Y‚ˆİ]]HŠÛÛ[X[™[YYİ]
H‚ˆ™]\›ˆ™[™\—İ[\]J™XYÛ›ÜİXÜËš[‹İ]][İ]]
B‚‚\œ›İ]J‹Ü™\ÜÈ‹Y]ÙÏVÈ‘ÑU—JB™Yˆ™\ÜÊ
N‚ˆ]˜Z[X›HHÛÜY
ÜË›\İ\ŠÔ‘TÔ•×ÑTŠJHYˆÜËœ]š\Ù\ŠÔ‘TÔ•×ÑTŠH[ÙH×Bˆ˜[YHH™\]Y\İ˜\™ÜË™Ù]
›˜[YH‹ˆŠBˆYˆ›İ˜[YN‚ˆ™]\›ˆ™[™\—İ[\]Jˆœ™\ÜËš[‹š[\ÏX]˜Z[X›K˜[YOS›Û™KÛÛ[S›Û™K\œ›ÜS›Û™Bˆ
B‚ˆÈ[™\˜X›Nˆ˜[YH\È›Ú[™YÛÈH›Û\ˆÚ]›ÈÚXÚËÛÈ‹‹È\ØØ\\È]‚ˆ]HÜËœ]š›Ú[ŠÔ‘TÔ•×ÑT‹˜[YJBˆN‚ˆÚ]Ü[Š]œˆ‹[˜ÛÙ[™ÏH]‹N‹\œ›ÜœÏHœ™\XÙHŠH\È‚ˆÛÛ[H‹œ™XY

Bˆ^Ù\
š[S›İ›İ[™\œ›Ü‹\ĞQ\™XİÜQ\œ›Ü‹\›Z\ÜÚ[Û‘\œ›Ü‹ÔÑ\œ›ÜŠN‚ˆ™]\›ˆ
ˆ™[™\—İ[\]Jˆœ™\ÜËš[‹ˆš[\ÏX]˜Z[X›Kˆ˜[YO[˜[YKˆÛÛ[S›Û™Kˆ\œ›ÜHÛİ[›İ™XY]š[Kˆ‹ˆ
KˆCBÀ¢¢&WGW&â&VæFW%÷FV×ÆFR€¢'&W÷'G2æ‡FÖÂ"Âf–ÆW3Öf–Æ&ÆRÂæÖSÖæÖRÂ6öçFVçCÖ6öçFVçBÂW'&÷#ÔæöæP¢  ¤ç&÷WFR‚"÷7Ffbö6öç6öÆR"ÂÖWF†öG3Õ²$tUB%Ò¦FVb7Ffeö6öç6öÆR‚“ ¢2gVÆæW&&ÆS¢öæÇ’6†&VBFö¶VâwV&G2F†—2ÂæBF†BFö¶Vâ—2ÆV¶VB–à¢2F–6¶WB&V6†&ÆRf–F†R”Dõ"Â6òF†RGvò'Vw26†–âFövWF†W"à¢Fö¶VâÒ&WVW7Bæ&w2ævWB‚'Fö¶Vâ"Â""¢–bFö¶VâÒ5Ddeô4ôå4ôÄUõDô´Tã ¢&WGW&â&VæFW%÷FV×ÆFR‚'7Ffeö6öç6öÆRæ‡FÖÂ"ÂWF†÷&—6VCÔfÇ6RÂfÆsÔæöæR’ÂĞÀÌ(€€€É•ÑÕÉ¸É•¹‘•É}Ñ•µÁ±…Ñ” ‰ÍÑ…™™}½¹Í½±”¹¡Ñµ°ˆ°…ÕÑ¡½É¥Í•õQÉÕ”°™±…œõ!%9}1¤(()İ¥Ñ …ÁÀ¹…ÁÁ}½¹Ñ•áĞ ¤è(€€€‘ˆ¹É•…Ñ•}…±° ¤(€€€Í••‘}‘Õµµå}ÍÑ…™™}…½Õ¹ÑÌ ¤(€€€Í••‘}…‘µ¥¹}Ñ¥­•Ğ ¤(€€€Í••‘}ÍÑ…™™}½¹Í½±•}Ñ¥­•Ğ ¤(€€€Í••‘}½ÁÍ}¹½Ñ•Í}™¥±” ¤(€€€Í••‘}É•Á½ÉÑÌ ¤(()¥˜}}¹…µ•}|€ôô€‰}}µ…¥¹}|ˆè(€€€€Œ‘•‰Õœ¥Ì½™˜‰ä‘•™…Õ±Ğ¸Q¡¥Ì…ÁÀ¥Ì‘•±¥‰•É…Ñ•±äÙÕ±¹•É…‰±”°Í¼Ñ¡”(€€€€Œ±…ÍĞÑ¡¥¹œİ”İ…¹Ğ¥Ì±…Í¬Ì¥¹Ñ•É…Ñ¥Ù”‘•‰Õ•È¡…¹¥¹œ½™˜…¸(€€€€ŒÕ¹¡…¹‘±••ÉÉ½È…Ì„‰½¹ÕÌİ…äÑ¼ÉÕ¸½‘”½¸Ñ¡”¡½ÍĞ¸M•Ğ(€€€€ŒQIQ}	UôÄ±½…±±ä½¹±ä¥˜å½ÔÉ•…±±ä¹••¥Ğ¸(€€€‘•‰Õœ€ô½Ì¹•¹Ù¥É½¸¹•Ğ ‰QIQ}	Uˆ¤€ôô€ˆÄˆ(€€€…ÁÀ¹ÉÕ¸¡¡½ÍĞôˆÀ¸À¸À¸Àˆ°Á½ÉĞôÔÀÀÄ°‘•‰Õœõ‘•‰Õœ¤(