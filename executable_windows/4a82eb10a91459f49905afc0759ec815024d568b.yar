import "pe"

rule INDICATOR_KB_CERT_282a8a04073eced658b9770bda8c0d28
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5cd4832101eb4f173c43986d5711087c8de25e6fcaef2f333e98a013e29b8373"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Betamaynd" and pe.signatures[i].serial=="28:2a:8a:04:07:3e:ce:d6:58:b9:77:0b:da:8c:0d:28")
}
