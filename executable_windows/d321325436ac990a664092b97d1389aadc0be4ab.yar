import "pe"

rule INDICATOR_KB_CERT_b548765eebe9468348af40b9891c1e63
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5987703bc4a3c739f92af8fed1747394880e1a39"
		hash1 = "501dee454ba470aa09ceceb4c93ab7e9e913729e47fcc184a2e2d675f8234a58"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OSIRIS Corporation" and pe.signatures[i].serial=="b5:48:76:5e:eb:e9:46:83:48:af:40:b9:89:1c:1e:63")
}
