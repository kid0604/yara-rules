import "pe"

rule INDICATOR_KB_CERT_2a2f270535c2d5e7630720fb229b5d1c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "73a0cc4495a49492806b970fd844a0ab078126930305d22c7bf68b43c337fc1a"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOZUZ SP. Z O.O." and pe.signatures[i].serial=="2a:2f:27:05:35:c2:d5:e7:63:07:20:fb:22:9b:5d:1c")
}
