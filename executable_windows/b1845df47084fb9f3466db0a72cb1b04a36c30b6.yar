import "pe"

rule INDICATOR_KB_CERT_11a9bf6b2dcbc683475b431a1c79133e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7412b3f5ba689967a5b46e6ef5dc5e9b9de3917d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BINDOX" and pe.signatures[i].serial=="11:a9:bf:6b:2d:cb:c6:83:47:5b:43:1a:1c:79:13:3e")
}
