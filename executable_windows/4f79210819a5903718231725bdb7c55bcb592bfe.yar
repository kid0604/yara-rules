import "pe"

rule INDICATOR_KB_CERT_085b70224253486624fc36fa658a1e32
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "36834eaf0061cc4b89a13e019eccc6e598657922"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Best Fud, OOO" and pe.signatures[i].serial=="08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32")
}
