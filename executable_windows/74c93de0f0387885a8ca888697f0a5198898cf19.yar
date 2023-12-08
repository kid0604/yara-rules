import "pe"

rule INDICATOR_KB_CERT_0086e5a9b9e89e5075c475006d0ca03832
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "76f6c507e0bcf7c6b881f117936f5b864a3bd3f8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BlueMarble GmbH" and pe.signatures[i].serial=="00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32")
}
