import "pe"

rule INDICATOR_KB_CERT_7bd36898217b4cc6b6427dd7c361e43d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c55df31aa16adb1013612ceb1dcf587afb7832c3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aeafefcafbafbaf" and pe.signatures[i].serial=="7b:d3:68:98:21:7b:4c:c6:b6:42:7d:d7:c3:61:e4:3d")
}
