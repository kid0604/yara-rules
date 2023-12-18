import "pe"

rule INDICATOR_KB_CERT_6000f8c02b0a15b1e53b8399845faddf
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6f18caa7cd75582d3a311dcc2dadec2ed32e15261c1dc5c9471e213d28367362"
		reason = "Amadey"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAY LIMITED" and pe.signatures[i].serial=="60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df")
}
