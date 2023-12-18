import "pe"

rule INDICATOR_KB_CERT_26f855a25890b749578f13e4b9459768
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7c81ba35732d1998def02461217cfd723150151bc93375a3e27c2cec33915660"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Boo’s Q & Sweets Corporation" and pe.signatures[i].serial=="26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68")
}
