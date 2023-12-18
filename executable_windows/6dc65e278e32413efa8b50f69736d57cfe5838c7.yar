import "pe"

rule INDICATOR_KB_CERT_698ff388adb50b88afb832e76b0a0ad1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "479e01dde7e7529ed4ad111a2d7b3b16fdc6fbe2ed0d6ff015c1c823ca0939db"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BELLAP LIMITED" and pe.signatures[i].serial=="69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1")
}
