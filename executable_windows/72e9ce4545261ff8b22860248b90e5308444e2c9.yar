import "pe"

rule INDICATOR_KB_CERT_07bb6a9d1c642c5973c16d5353b17ca4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "9de562e98a5928866ffc581b794edfbc249a2a07"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MADAS d.o.o." and pe.signatures[i].serial=="07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4")
}
