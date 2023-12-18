import "pe"

rule INDICATOR_KB_CERT_77550ed697992b397e3f1ad8e2a662d1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0c439c7b60714158f62c45921caf30d17dae37ec6cbc2dfdd9d306e18ae6df63"
		reason = "ParallaxRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GRASS RAIN, s.r.o." and pe.signatures[i].serial=="77:55:0e:d6:97:99:2b:39:7e:3f:1a:d8:e2:a6:62:d1")
}
