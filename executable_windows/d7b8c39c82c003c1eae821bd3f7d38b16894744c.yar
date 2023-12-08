import "pe"

rule INDICATOR_KB_CERT_4f5a9bf75da76b949645475473793a7d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "f7de21bbdf5effb0f6739d505579907e9f812e6f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and pe.signatures[i].serial=="4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d")
}
