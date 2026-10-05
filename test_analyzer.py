import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from email_analyzer import analyse, assess_url  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_legit_is_clean():
    assert analyse(SAMPLES / "01-legit-newsletter.eml").verdict == "CLEAN"


def test_credential_phish_is_malicious():
    r = analyse(SAMPLES / "02-credential-phish.eml")
    assert r.verdict == "MALICIOUS"
    details = " ".join(f.detail for f in r.findings)
    assert "DMARC fail" in details and "Reply-To" in details and "link text shows" in details


def test_attachment_phish_is_malicious():
    r = analyse(SAMPLES / "03-malicious-attachment.eml")
    assert r.verdict == "MALICIOUS"
    assert {a["name"] for a in r.attachments} == {"INV-20931.xlsm", "remittance.pdf.zip"}
    assert all(len(a["sha256"]) == 64 for a in r.attachments)


def test_url_lookalikes():
    assert any("look-alike" in d for _, d, _ in assess_url("https://paypa1-login.example/", ""))
    assert assess_url("https://www.paypal.com/au/home", "paypal.com") == []


def test_display_name_spoof(tmp_path):
    m = EmailMessage()
    m["From"] = '"PayPal Support" <help@random-mailer.example>'
    m["Subject"] = "hello"
    m.set_content("hi")
    f = tmp_path / "x.eml"
    f.write_bytes(bytes(m))
    r = analyse(f)
    assert any("Display name" in x.detail for x in r.findings)
