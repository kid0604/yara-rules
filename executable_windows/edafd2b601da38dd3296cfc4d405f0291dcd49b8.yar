import "pe"

rule INDICATOR_KB_CERT_1a311630876f694fe1b75d972a953bca
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d473ec0fe212b7847f1a4ee06eff64e2a3b4001e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GTEC s.r.o." and pe.signatures[i].serial=="1a:31:16:30:87:6f:69:4f:e1:b7:5d:97:2a:95:3b:ca")
}
