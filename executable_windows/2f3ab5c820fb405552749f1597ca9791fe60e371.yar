import "pe"

rule INDICATOR_KB_CERT_5143cf38d5fd26858830826632be9fda
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "57a8aa854f3198f069bb34bc763b7773a8cfdafb562ee0ccf24a5067d45d5e3c"
		reason = "BumbleBee"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIGI CORP MEDIA LLC" and pe.signatures[i].serial=="51:43:cf:38:d5:fd:26:85:88:30:82:66:32:be:9f:da")
}
