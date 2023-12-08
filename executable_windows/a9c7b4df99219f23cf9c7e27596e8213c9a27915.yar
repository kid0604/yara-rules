import "pe"

rule INDICATOR_KB_CERT_6ba32f984444ea464bea41d99a977ea8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "ae9e65e26275d014a4a8398569af5eeddf7a472c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JIN CONSULTANCY LIMITED" and pe.signatures[i].serial=="6b:a3:2f:98:44:44:ea:46:4b:ea:41:d9:9a:97:7e:a8")
}
