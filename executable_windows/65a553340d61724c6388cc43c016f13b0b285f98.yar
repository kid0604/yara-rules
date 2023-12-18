import "pe"

rule INDICATOR_KB_CERT_dbc03ca7e6ae6db6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e059776cb5e640569a06c2548e87af5bd655f5d4815b8f6e9482835455930987"
		reason = "CobaltStrike"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIDER DEVELOPMENTS PTY LTD" and pe.signatures[i].serial=="db:c0:3c:a7:e6:ae:6d:b6")
}
