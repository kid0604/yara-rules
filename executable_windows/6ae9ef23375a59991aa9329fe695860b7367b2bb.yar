import "pe"

rule INDICATOR_KB_CERT_2924785fd7990b2d510675176dae2bed
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "adbc44fda783b5fa817f66147d911fb81a0e2032a1c1527d1b3adbe55f9d682d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Neoopt LLC" and pe.signatures[i].serial=="29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed")
}
