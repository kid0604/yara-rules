import "pe"

rule INDICATOR_KB_CERT_6401831b46588b9d872b02076c3a7b00
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "19fc95ac815865e8b57c80ed21a22e2c0fecc1ff"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIV GROUP ApS" and pe.signatures[i].serial=="64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00")
}
