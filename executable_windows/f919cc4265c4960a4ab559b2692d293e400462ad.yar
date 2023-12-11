import "pe"

rule INDICATOR_KB_CERT_00cc95d6ebf18a3711e196aea210465a19
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "319f0e03f0f230629258c7ea05e7d56ead830ce9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GEN Sistemi, d.o.o." and pe.signatures[i].serial=="00:cc:95:d6:eb:f1:8a:37:11:e1:96:ae:a2:10:46:5a:19")
}
