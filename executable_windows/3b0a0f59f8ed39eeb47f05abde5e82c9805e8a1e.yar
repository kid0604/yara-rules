import "pe"

rule INDICATOR_KB_CERT_3d2580e89526f7852b570654efd9a8bf
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c1b4d57a36e0b6853dd38e3034edf7d99a8b73ad"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MIKL LIMITED" and pe.signatures[i].serial=="3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf")
}
