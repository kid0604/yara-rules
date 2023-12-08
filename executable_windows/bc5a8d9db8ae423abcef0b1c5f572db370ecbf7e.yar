import "pe"

rule INDICATOR_KB_CERT_00bd96f0b87edca41e777507015b3b2775
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "abfa72d4a78a9e63f97c90bcccb8f46f3c14ac52"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ООО \"СМ\"" and (pe.signatures[i].serial=="bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75" or pe.signatures[i].serial=="00:bd:96:f0:b8:7e:dc:a4:1e:77:75:07:01:5b:3b:27:75"))
}
