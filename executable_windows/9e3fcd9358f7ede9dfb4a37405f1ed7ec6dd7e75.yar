import "pe"

rule INDICATOR_KB_CERT_121070be1e782f206985543bc7bc58b6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a4534aff03258589a2622398d1904d3bfd264c37e8649a68136f8d552f8b738f"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Prod Can Holdings Inc." and pe.signatures[i].serial=="12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6")
}
