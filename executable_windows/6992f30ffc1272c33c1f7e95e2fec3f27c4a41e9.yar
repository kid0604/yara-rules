import "pe"

rule INDICATOR_KB_CERT_0772b4d1d63233d2b8771997bc8da5c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c6a78692f2fda8908933fb3f1df68592eb5da129caafd33329d1b804006973f7"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maya logistika d.o.o." and pe.signatures[i].serial=="07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4")
}
