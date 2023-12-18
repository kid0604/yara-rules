import "pe"

rule INDICATOR_KB_CERT_05d50a0e09bb9a836ffb90a3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2d072e0e80885a82d5e35806b052ca416994e0fe06da1cfdcebd509d967a1aae"
		reason = "ParallaxRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Toliz Info Tech Solutions INC." and pe.signatures[i].serial=="05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3")
}
