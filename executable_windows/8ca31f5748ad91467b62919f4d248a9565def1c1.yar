import "pe"

rule INDICATOR_KB_CERT_58af00ce542760fc116b41fa92e18589
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "620dafea381ab657e0335321ca5a95077f33021927a32d5d62bff7e33704f4b7"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DICKIE MUSDALE WINDFARM LIMITED" and pe.signatures[i].serial=="58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89")
}
