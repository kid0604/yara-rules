import "pe"

rule INDICATOR_KB_CERT_02de1cc6c487954592f1bf574ca2b000
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e35804bbf4573f492c51a7ad7a14557816fe961f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orca System" and pe.signatures[i].serial=="02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00")
}
