import "pe"

rule INDICATOR_KB_CERT_3b0914e2982be8980aa23f49848555e5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "254e59ea93fa5f2a6af44f9631660f7b6cca4b4c9f97046405bcfed5589a32fa"
		reason = "ParallaxRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Office Rat s.r.o." and pe.signatures[i].serial=="3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5")
}
