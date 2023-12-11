import "pe"

rule INDICATOR_KB_CERT_72f3e4707b94d0eef214384de9b36e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e2a5a2823b0a56c88bfcb2788aa4406e084c4c9b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eaaebecedccfd" and pe.signatures[i].serial=="72:f3:e4:70:7b:94:d0:ee:f2:14:38:4d:e9:b3:6e")
}
