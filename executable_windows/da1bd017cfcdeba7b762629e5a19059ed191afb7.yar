import "pe"

rule INDICATOR_KB_CERT_69ad1e8b5941c93d5017b7c3fdb8e7b6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9b6f3b3cd33ae938fbc5c95b8c9239bac9f9f7bf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Afia Wave Enterprises Oy" and pe.signatures[i].serial=="69:ad:1e:8b:59:41:c9:3d:50:17:b7:c3:fd:b8:e7:b6")
}
