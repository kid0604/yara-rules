import "pe"

rule INDICATOR_KB_CERT_51cd5393514f7ace2b407c3dbfb09d8d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "07a9fd6af84983dbf083c15983097ac9ce761864"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APPI CZ a.s" and pe.signatures[i].serial=="51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d")
}
