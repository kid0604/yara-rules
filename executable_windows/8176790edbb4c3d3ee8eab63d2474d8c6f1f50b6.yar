import "pe"

rule INDICATOR_KB_CERT_0406c4a1521a38c8d0c4aa214388e4dc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7d6dc731d94c9aaf241f3df940ce8ca8393380b12f92e872273ae747c5d4791f"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Venezia Design SRL" and pe.signatures[i].serial=="04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc")
}
