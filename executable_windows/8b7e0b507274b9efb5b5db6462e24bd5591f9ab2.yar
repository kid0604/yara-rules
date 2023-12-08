import "pe"

rule INDICATOR_KB_CERT_262ca7ae19d688138e75932832b18f9d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c5d34eb26bbb3fcb274f9e9cb37f5ae6612747a1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and pe.signatures[i].serial=="26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d")
}
