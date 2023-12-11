import "pe"

rule INDICATOR_KB_CERT_26279f0f2f11970dccf63eba88f2d4c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d4fb2982268b592e3cd46fa78194e71418297741"
		hash = "a3af3d7e825daeffc05e34a784d686bb9f346d48a92c060e1e901c644398d5d7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Qihoo 360 Software (Beijing) Company Limited" and pe.signatures[i].serial=="26:27:9f:0f:2f:11:97:0d:cc:f6:3e:ba:88:f2:d4:c4")
}
