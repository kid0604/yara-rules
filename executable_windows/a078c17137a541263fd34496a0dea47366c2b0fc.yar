import "pe"

rule INDICATOR_KB_CERT_23389161e45a218bd24e6e859ae11153
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "978859ce5698f2bfade1129401cf70856be738d3"
		hash = "a3af3d7e825daeffc05e34a784d686bb9f346d48a92c060e1e901c644398d5d7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Qihoo 360 Software (Beijing) Company Limited" and pe.signatures[i].serial=="23:38:91:61:e4:5a:21:8b:d2:4e:6e:85:9a:e1:11:53")
}
