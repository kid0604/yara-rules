import "pe"

rule INDICATOR_KB_CERT_54a6d33f73129e0ef059ccf51be0c35e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8ada307ab3a8983857d122c4cb48bf3b77b49c63"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and pe.signatures[i].serial=="54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e")
}
