import "pe"

rule INDICATOR_KB_CERT_2f184a6f054dc9f7c74a63714b14ce33
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed AprelTech Silent Install Builder certificate"
		thumbprint = "ec9c6a537f6d7a0e63a4eb6aeb0df9d5b466cc58"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APREL Tehnologija d.o.o." and pe.signatures[i].serial=="2f:18:4a:6f:05:4d:c9:f7:c7:4a:63:71:4b:14:ce:33")
}
