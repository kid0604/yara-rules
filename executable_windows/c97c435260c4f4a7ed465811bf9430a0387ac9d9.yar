import "pe"

rule INDICATOR_KB_CERT_1e72a72351aecf884df9cdb77a16fd84
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f945bbea1c2e2dd4ed17f5a98ea7c0f0add6bfc3d07353727b40ce48a7d5e48f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Buket and Co." and pe.signatures[i].serial=="1e:72:a7:23:51:ae:cf:88:4d:f9:cd:b7:7a:16:fd:84")
}
