import "pe"

rule INDICATOR_KB_CERT_333705c20b56e57f60b5eb191eef0d90
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "44f0f77d8b649579fa6f88ae9fa4b4206b90b120"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK Holding ApS" and pe.signatures[i].serial=="33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90")
}
