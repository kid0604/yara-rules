import "pe"

rule INDICATOR_KB_CERT_eee8cf0a0e4c78faa03d07470161a90e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "32eda5261359e76a4e66da1ba82db7b7a48295d2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aafabffdbdbcbfcaebdf" and pe.signatures[i].serial=="ee:e8:cf:0a:0e:4c:78:fa:a0:3d:07:47:01:61:a9:0e")
}
