import "pe"

rule INDICATOR_KB_CERT_70e1ebd170db8102d8c28e58392e5632
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "90d67006be03f2254e1da76d4ea7dc24372c4f30b652857890f9d9a391e9279c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Equal Cash Technologies Limited" and pe.signatures[i].serial=="70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32")
}
