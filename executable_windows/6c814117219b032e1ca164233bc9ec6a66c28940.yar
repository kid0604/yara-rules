import "pe"

rule INDICATOR_KB_CERT_e5bf5b5c0880db96477c24c18519b9b9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = ""
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WATWGHFC" and pe.signatures[i].serial=="e5:bf:5b:5c:08:80:db:96:47:7c:24:c1:85:19:b9:b9")
}
