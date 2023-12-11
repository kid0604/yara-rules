import "pe"

rule INDICATOR_KB_CERT_3e57584db26a2c2ebc24ae3e1954fff6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4ecbada12a11a5ad5fe6a72a8baaf9d67dc07556a42f6e9a9b6765e334099f4e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zaryad LLC" and pe.signatures[i].serial=="3e:57:58:4d:b2:6a:2c:2e:bc:24:ae:3e:19:54:ff:f6")
}
