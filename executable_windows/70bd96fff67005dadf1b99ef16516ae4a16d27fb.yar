import "pe"

rule INDICATOR_KB_CERT_e3c7cc0950152e9ceead4304d01f6c89
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "82975e3e21e8fd37bb723de6fdb6e18df9d0e55f0067cc77dd571a52025c6724"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DNS KOMPLEKT" and pe.signatures[i].serial=="e3:c7:cc:09:50:15:2e:9c:ee:ad:43:04:d0:1f:6c:89")
}
