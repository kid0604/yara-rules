import "pe"

rule INDICATOR_KB_CERT_da156922f4760e0c5f5bcf79812a27e1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6e19e012f55e0bb44e9036d4445ab945942965dcb81b9ed24ad6fc17933c4fce"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DRINK AND BUBBLE LTD" and pe.signatures[i].serial=="da:15:69:22:f4:76:0e:0c:5f:5b:cf:79:81:2a:27:e1")
}
