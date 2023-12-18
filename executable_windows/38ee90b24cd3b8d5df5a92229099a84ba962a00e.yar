import "pe"

rule INDICATOR_KB_CERT_fecc3b3c675f7ffd7de22507f3fdacd7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6b8cc2be066ff0bf1d884892fc600482fc34eaddb3a5e6681b509d64795b01d4"
		reason = "RemcosRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gromit Electronics Limited" and pe.signatures[i].serial=="fe:cc:3b:3c:67:5f:7f:fd:7d:e2:25:07:f3:fd:ac:d7")
}
