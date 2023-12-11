import "pe"

rule INDICATOR_KB_CERT_289051a83f350a2c600187c99b6c0a73
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4e075adea8c1bcb9d10904203ab81965f4912ff0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and pe.signatures[i].serial=="28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73")
}
