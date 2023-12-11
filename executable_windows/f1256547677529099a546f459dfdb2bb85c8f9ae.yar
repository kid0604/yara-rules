import "pe"

rule INDICATOR_KB_CERT_7c1118cbbadc95da3752c46e47a27438
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5b9e273cf11941fd8c6be3f038c4797bbe884268"
		hash1 = "f8da3ee80f71b994d8921f9d902456cbd5187e1bdcd352a81f1d76e0f50ca0b8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Simon Tatham" and pe.signatures[i].serial=="7c:11:18:cb:ba:dc:95:da:37:52:c4:6e:47:a2:74:38")
}
