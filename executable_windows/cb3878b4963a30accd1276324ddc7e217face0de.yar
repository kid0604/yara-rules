import "pe"

rule INDICATOR_KB_CERT_00a496bc774575c31abec861b68c36dcb6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b2c70d30c0b34bfeffb8a9cb343e5cad5f6bcbf7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and pe.signatures[i].serial=="00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6")
}
