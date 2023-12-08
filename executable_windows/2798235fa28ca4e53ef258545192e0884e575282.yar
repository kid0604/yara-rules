import "pe"

rule INDICATOR_KB_CERT_fbe6758ae785d7c678a4ad8de5c3f7e6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bd1958f0306fc8699e829541cd9b8c4fe0e0c6da920932f2cd4d78ed76bda426"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HORUM" and pe.signatures[i].serial=="fb:e6:75:8a:e7:85:d7:c6:78:a4:ad:8d:e5:c3:f7:e6")
}
