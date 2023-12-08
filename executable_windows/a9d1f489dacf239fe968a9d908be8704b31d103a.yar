import "pe"

rule INDICATOR_KB_CERT_56203db039adbd6094b6a142c5e50587
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e438c77483ecab0ff55cc31f2fd2f835958fad80"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bccabdacabbdcda" and pe.signatures[i].serial=="56:20:3d:b0:39:ad:bd:60:94:b6:a1:42:c5:e5:05:87")
}
