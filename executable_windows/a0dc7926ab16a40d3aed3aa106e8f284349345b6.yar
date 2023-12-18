import "pe"

rule INDICATOR_KB_CERT_1614ef66b2c4b886e71a93dd34869f48
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1689697e08dda6d1233c0056078ddf25b12c3608ead7d96ed4cbbb074e54ce29"
		reason = "RemcosRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHIRT AND CUFF LIMITED" and pe.signatures[i].serial=="16:14:ef:66:b2:c4:b8:86:e7:1a:93:dd:34:86:9f:48")
}
