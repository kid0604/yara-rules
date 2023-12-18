import "pe"

rule INDICATOR_KB_CERT_5226a724cfa0b4bc0164ecda3f02a3dc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "92f005b9c46c7993205d9451823cf0410d1afbd7056a7dcdfa2b8b3da74ee1bf"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VALENTE SP Z O O" and pe.signatures[i].serial=="52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc")
}
