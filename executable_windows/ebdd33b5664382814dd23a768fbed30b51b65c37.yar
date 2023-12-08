import "pe"

rule INDICATOR_KB_CERT_20a20dfce424e6bbcc162a5fcc0972ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "1d25a769f7ff0694d333648acea3f18b323bc9f1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TeamViewer GmbH" and pe.signatures[i].serial=="20:a2:0d:fc:e4:24:e6:bb:cc:16:2a:5f:cc:09:72:ee")
}
