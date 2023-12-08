import "pe"

rule INDICATOR_KB_CERT_0292c7d574132ba5c0441d1c7ffcb805
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d0ae777a34d4f8ce6b06755c007d2d92db2a760c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and pe.signatures[i].serial=="02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05")
}
