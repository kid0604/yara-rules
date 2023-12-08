import "pe"

rule INDICATOR_KB_CERT_726ee7f5999b9e8574ec59969c04955c
{
	meta:
		author = "ditekSHen"
		description = "Detects IntelliAdmin commercial remote administration signing certificate"
		thumbprint = "2fb952bc1e3fcf85f68d6e2cb5fc46a519ce3fa9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IntelliAdmin, LLC" and pe.signatures[i].serial=="72:6e:e7:f5:99:9b:9e:85:74:ec:59:96:9c:04:95:5c")
}
