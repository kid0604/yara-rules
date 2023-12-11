import "pe"

rule INDICATOR_KB_CERT_2bffef48e6a321b418041310fdb9b0d0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c40c5157e96369ceb7e26e756f2d1372128cee7b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A&D DOMUS LIMITED" and pe.signatures[i].serial=="2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0")
}
