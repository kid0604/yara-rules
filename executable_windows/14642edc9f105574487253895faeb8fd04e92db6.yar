import "pe"

rule INDICATOR_KB_CERT_4c8def294478b7d59ee95c61fae3d965
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = ""
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREAM SECURITY USA INC" and pe.signatures[i].serial=="4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65")
}
