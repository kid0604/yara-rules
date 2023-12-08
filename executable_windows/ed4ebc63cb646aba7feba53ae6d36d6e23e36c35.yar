import "pe"

rule INDICATOR_KB_CERT_00a758504e7971869d0aec2775fffa03d5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "646bbb3a37cc004bea6efcd48579d1a5776cb157"
		hash1 = "3194e2fb68c007cf2f6deaa1fb07b2cc68292ee87f37dff70ba142377e2ca1fa"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amcert LLC" and (pe.signatures[i].serial=="a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or pe.signatures[i].serial=="00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"))
}
