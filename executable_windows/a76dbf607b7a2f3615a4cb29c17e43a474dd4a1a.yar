import "pe"

rule INDICATOR_KB_CERT_08622b9dd9d78e67678ecc21e026522e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a7d86073742ea55af134e07a00aefa355dc123be"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and pe.signatures[i].serial=="08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e")
}
