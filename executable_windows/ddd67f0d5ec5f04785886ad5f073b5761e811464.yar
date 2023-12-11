import "pe"

rule INDICATOR_KB_CERT_5029daca439511456d9ed8153703f4bc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "9d5ded35ffd34aa78273f0ebd4d6fa1e5337ac2b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE GREEN PARTNERSHIP LTD" and pe.signatures[i].serial=="50:29:da:ca:43:95:11:45:6d:9e:d8:15:37:03:f4:bc")
}
