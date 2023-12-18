import "pe"

rule INDICATOR_KB_CERT_74fc9257bc86f8c618501695ad4b1606
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8ebbb2ab8f2e1366d0137e5026e07fde229f45f39d043c7ad36091b8eb2a923e"
		reason = "ParallaxRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "169Teaco Limited" and pe.signatures[i].serial=="74:fc:92:57:bc:86:f8:c6:18:50:16:95:ad:4b:16:06")
}
