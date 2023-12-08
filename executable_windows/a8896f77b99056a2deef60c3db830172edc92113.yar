import "pe"

rule INDICATOR_KB_CERT_066226cf6a4d8ae1100961a0c5404ff9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "8c762918a58ebccb1713720c405088743c0d6d20"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO MEP" and pe.signatures[i].serial=="06:62:26:cf:6a:4d:8a:e1:10:09:61:a0:c5:40:4f:f9")
}
