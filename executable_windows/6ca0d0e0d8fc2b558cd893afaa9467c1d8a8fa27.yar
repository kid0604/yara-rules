import "pe"

rule INDICATOR_KB_CERT_06bcb74291d96096577bdb1e165dce85
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d1bde6303266977f7540221543d3f2625da24ac4"
		hash1 = "074cef597dc028b08dc2fe927ea60f09cfd5e19f928f2e4071860b9a159b365d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Revo Security SRL" and pe.signatures[i].serial=="06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85")
}
