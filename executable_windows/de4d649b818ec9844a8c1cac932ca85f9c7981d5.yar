import "pe"

rule INDICATOR_KB_CERT_69a72f5591ad78a0825fbb9402ab9543
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "42a6612f4c652b521435989b5f044403649fef6db4fb476f3c4d981dc2f9bdf8"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PUSH BANK LIMITED" and pe.signatures[i].serial=="69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43")
}
