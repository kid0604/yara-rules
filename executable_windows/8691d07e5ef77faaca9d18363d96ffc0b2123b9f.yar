import "pe"

rule INDICATOR_KB_CERT_4728189fa0f57793484cdf764f5e283d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "89ff94ac1c577eced3afc9a81689d30ca238a8472ad0f025f6bed57a98dbb273"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Power Save Systems s.r.o." and pe.signatures[i].serial=="47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d")
}
