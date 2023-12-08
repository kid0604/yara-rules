import "pe"

rule INDICATOR_KB_CERT_09c89de6f64a7fdf657e69353c5fdd44
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "7ad763dfdaabc1c5a8d1be582ec17d4cdcbd1aeb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and pe.signatures[i].serial=="09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44")
}
