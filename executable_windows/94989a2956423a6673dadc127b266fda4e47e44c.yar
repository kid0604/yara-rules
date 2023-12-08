import "pe"

rule INDICATOR_KB_CERT_4e8d4fc7d9f38aca1169fbf8ef2aaf50
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "7239764d40118fc1574a0af77a34e369971ddf6d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "INFINITE PROGRAMMING LIMITED" and pe.signatures[i].serial=="4e:8d:4f:c7:d9:f3:8a:ca:11:69:fb:f8:ef:2a:af:50")
}
