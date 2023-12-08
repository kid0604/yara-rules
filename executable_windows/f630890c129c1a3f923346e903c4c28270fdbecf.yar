import "pe"

rule INDICATOR_KB_CERT_768ddcf9ed8d16a6bc77451ee88dfd90
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = ""
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THEESOLUTIONS LTD" and pe.signatures[i].serial=="76:8d:dc:f9:ed:8d:16:a6:bc:77:45:1e:e8:8d:fd:90")
}
