import "pe"

rule INDICATOR_KB_CERT_5f7ef778d51cd33a5fc0d2e035ccd29d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "87229a298b8de0c7b8d4e23119af1e7850a073f5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ffadbcfabbe" and pe.signatures[i].serial=="5f:7e:f7:78:d5:1c:d3:3a:5f:c0:d2:e0:35:cc:d2:9d")
}
