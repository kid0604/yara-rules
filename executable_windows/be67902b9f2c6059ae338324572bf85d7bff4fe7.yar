import "pe"

rule INDICATOR_KB_CERT_31d852f5fca1a5966b5ed08a14825c54
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a657b8f2efea32e6a1d46894764b7a4f82ad0b56"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BBT KLA d.o.o." and pe.signatures[i].serial=="31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54")
}
