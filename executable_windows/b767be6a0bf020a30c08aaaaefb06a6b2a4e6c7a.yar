import "pe"

rule INDICATOR_KB_CERT_3d568325dec56abf48e72317675cacb7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "e5b21024907c9115dafccc3d4f66982c7d5641bc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Virtual Byte F-B-I" and pe.signatures[i].serial=="3d:56:83:25:de:c5:6a:bf:48:e7:23:17:67:5c:ac:b7")
}
