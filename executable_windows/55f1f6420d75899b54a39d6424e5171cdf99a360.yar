import "pe"

rule INDICATOR_KB_CERT_333ca7d100b139b0d9c1a97cb458e226
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d618cf7ef3a674ff1ea50800b4d965de0ff463cb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FSE, d.o.o." and pe.signatures[i].serial=="33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26")
}
