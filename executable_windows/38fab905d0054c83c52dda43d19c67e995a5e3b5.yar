import "pe"

rule INDICATOR_KB_CERT_351fe2efdc0ac56a0c822cf8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "4230bca4b7e4744058a7bb6e355346ff0bbeb26f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logika OOO" and pe.signatures[i].serial=="35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8")
}
