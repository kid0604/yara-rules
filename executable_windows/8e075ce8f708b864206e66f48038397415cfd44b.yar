import "pe"

rule INDICATOR_KB_CERT_00e5ad42c509a7c24605530d35832c091e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "17b1f6ffc569acd2cf803c4ac24a7f9828d8d14f6b057e65efdb5c93cc729351"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VESNA, OOO" and pe.signatures[i].serial=="00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e")
}
