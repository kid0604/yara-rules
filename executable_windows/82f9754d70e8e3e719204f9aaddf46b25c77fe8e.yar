import "pe"

rule INDICATOR_KB_CERT_02b6656292310b84022db5541bc48faf
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bb58a3d322fd67122804b2924ad1ddc27016e11a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DILA d.o.o." and pe.signatures[i].serial=="02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af")
}
