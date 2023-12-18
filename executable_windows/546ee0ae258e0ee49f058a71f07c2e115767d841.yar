import "pe"

rule INDICATOR_KB_CERT_25ba18a267d6d8e08ebc6e2457d58d1e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e59824f73703461c2c170681872a28a9bc4731d4b49079aa3afba1d29f83d736"
		reason = "BadNews"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5Y TECHNOLOGY LIMITED" and pe.signatures[i].serial=="25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e")
}
