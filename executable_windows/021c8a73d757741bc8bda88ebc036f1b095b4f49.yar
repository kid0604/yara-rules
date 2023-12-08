import "pe"

rule INDICATOR_KB_CERT_5b320a2f46c99c1ba1357bee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "5ae8bd51ffa8e82f8f3d8297c4f9caf5e30f425a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REGION TOURISM LLC" and pe.signatures[i].serial=="5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee")
}
