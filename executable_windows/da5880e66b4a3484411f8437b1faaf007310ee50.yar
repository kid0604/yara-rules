import "pe"

rule INDICATOR_KB_CERT_03b630f9645531f8868dae8ac0f8cfe6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "ab027825daf46c5e686e4d9bc9c55a5d8c5e957d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Geksan LLC" and pe.signatures[i].serial=="03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6")
}
