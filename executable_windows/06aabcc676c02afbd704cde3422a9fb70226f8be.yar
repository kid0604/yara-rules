import "pe"

rule INDICATOR_KB_CERT_00913ba16962cd7eee25965a6d0eeffa10
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "079aeb295c8e27ac8d9be79c8b0aaf66a0ef15de"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JMT TRADING GROUP INC" and pe.signatures[i].serial=="00:91:3b:a1:69:62:cd:7e:ee:25:96:5a:6d:0e:ef:fa:10")
}
