import "pe"

rule INDICATOR_KB_CERT_00dfef1a8c0dbfef64bc6c8a0647d6e873
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0709cdcb27230171877e2a11e6646a9fde28e02c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NnTqRHlSFNJSUHGaiKWzqyHGdPzBarblmWEzpKHvkZrqn" and pe.signatures[i].serial=="00:df:ef:1a:8c:0d:bf:ef:64:bc:6c:8a:06:47:d6:e8:73")
}
