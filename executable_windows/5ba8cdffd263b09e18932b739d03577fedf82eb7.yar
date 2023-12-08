import "pe"

rule INDICATOR_KB_CERT_9aa99f1b75a463460d38c4539fae4f73
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b2ea9e771631f95a927c29b044284ef4f84a2069"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beaacdfaeeccbbedadcb" and pe.signatures[i].serial=="9a:a9:9f:1b:75:a4:63:46:0d:38:c4:53:9f:ae:4f:73")
}
