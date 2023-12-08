import "pe"

rule INDICATOR_KB_CERT_141d6dafed065980d97520e666493396
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "28225705d615a47de0d1b0e324b5b9ca7c11ce48"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ralph Schmidt" and pe.signatures[i].serial=="14:1d:6d:af:ed:06:59:80:d9:75:20:e6:66:49:33:96")
}
