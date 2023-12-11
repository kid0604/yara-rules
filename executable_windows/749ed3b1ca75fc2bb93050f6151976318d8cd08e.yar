import "pe"

rule INDICATOR_KB_CERT_387eeb89b8bf626bbf4c7c9f5b998b40
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e94ad249747fd4b88750b2cd6d8d65ad33d3566d"
		hash1 = "004f011b37e4446fa04b76aae537cc00f6588c0705839152ae2d8a837ef2b730"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and pe.signatures[i].serial=="38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40")
}
