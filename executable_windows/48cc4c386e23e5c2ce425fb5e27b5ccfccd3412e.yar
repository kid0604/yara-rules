import "pe"

rule INDICATOR_KB_CERT_28f6ca1f249cfb6bdb16bc57aaf0bd79
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0811c227816282094d5212d3c9116593f70077ab"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdcafaabbdcaaaeaaee" and pe.signatures[i].serial=="28:f6:ca:1f:24:9c:fb:6b:db:16:bc:57:aa:f0:bd:79")
}
