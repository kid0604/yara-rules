import "pe"

rule INDICATOR_KB_CERT_00aebe117a13b8bca21685df48c74f584d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4dc9713dfb079fbae4173d342ebeb4efb9b0a4dc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NANAX d.o.o." and pe.signatures[i].serial=="00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d")
}
