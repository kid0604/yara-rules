import "pe"

rule INDICATOR_KB_CERT_0deb004e56d7fcec1caa8f2928d4e768
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "21dacc55b6e0b3b0e761be03ed6edd713489b6ce"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC Mail.Ru" and pe.signatures[i].serial=="0d:eb:00:4e:56:d7:fc:ec:1c:aa:8f:29:28:d4:e7:68")
}
