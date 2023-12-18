import "pe"

rule INDICATOR_KB_CERT_061a27a3a3771bb440fc16cadf2675c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9ed703ba7033af5f88a5f5ef0155adc41715d3175eec836822a09a93d56e4b7f"
		reason = "Matanbuchus"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Westeast Tech Consulting, Corp." and pe.signatures[i].serial=="06:1a:27:a3:a3:77:1b:b4:40:fc:16:ca:df:26:75:c4")
}
