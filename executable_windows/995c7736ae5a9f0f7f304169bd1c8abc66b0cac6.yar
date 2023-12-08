import "pe"

rule INDICATOR_KB_CERT_3769815a97a8fb411e005282b37878e3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c80fd3259af331743e35a2197f5f57061654860c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Yandex" and pe.signatures[i].serial=="37:69:81:5a:97:a8:fb:41:1e:00:52:82:b3:78:78:e3")
}
