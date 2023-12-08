import "pe"

rule INDICATOR_KB_CERT_00e48cb3314977d77dedcd4c77dd144c50
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "025bce0f36ec5bac08853966270ed2f5e28765d9c398044462a28c67d74d71e1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BESPOKE SOFTWARE SOLUTIONS LIMITED" and pe.signatures[i].serial=="00:e4:8c:b3:31:49:77:d7:7d:ed:cd:4c:77:dd:14:4c:50")
}
