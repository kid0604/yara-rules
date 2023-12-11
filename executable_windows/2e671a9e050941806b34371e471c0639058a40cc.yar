import "pe"

rule INDICATOR_KB_CERT_7b91468122273aa32b7cfc80c331ea13
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "409f32dc91542546e7c7f85f687fe3f1acffdd853657c8aa8c1c985027f5271d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO KBI" and pe.signatures[i].serial=="7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13")
}
