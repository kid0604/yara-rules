import "pe"

rule INDICATOR_KB_CERT_29a248a77d5d4066fe5da75f32102bb5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "1078c0ab5766a48b0d4e04e57f3ab65b68dd797f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SUN & STARZ LIMITED" and pe.signatures[i].serial=="29:a2:48:a7:7d:5d:40:66:fe:5d:a7:5f:32:10:2b:b5")
}
