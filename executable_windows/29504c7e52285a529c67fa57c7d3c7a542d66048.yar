import "pe"

rule INDICATOR_KB_CERT_5a9d897077a22afe7ad4c4a01df6c418
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "50fa9d22557354a078767cb61f93de9abe491e3a8cb69c280796c7c20eabd5b9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Klarens LLC" and pe.signatures[i].serial=="5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18")
}
