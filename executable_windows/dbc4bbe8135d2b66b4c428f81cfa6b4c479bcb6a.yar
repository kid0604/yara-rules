import "pe"

rule INDICATOR_KB_CERT_890570b6b0e2868a53be3f8f904a88ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f291d21d72dcefc369526a97b7d39214544b22057757ac00907ab4ff3baa2edd"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JESEN LESS d.o.o." and pe.signatures[i].serial=="89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee")
}
