import "pe"

rule INDICATOR_KB_CERT_fdb6f4c09a1ad69d4fd2e46bb1f54313
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "4d1bc69003b1b1c3d0b43f6c17f81d13e0846ea7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FDSMMCME" and pe.signatures[i].serial=="fd:b6:f4:c0:9a:1a:d6:9d:4f:d2:e4:6b:b1:f5:43:13")
}
