import "pe"

rule INDICATOR_KB_CERT_00b0a308fc2e71ac4ac40677b9c27ccbad
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "15e502f1482a280f7285168bb5e227ffde4e41a6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Volpayk LLC" and pe.signatures[i].serial=="00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad")
}
