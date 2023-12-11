import "pe"

rule INDICATOR_KB_CERT_0382cd4b6ed21ed7c3eaea266269d000
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e600612ffcd002718b7d03a49d142d07c5a04154"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LOOK AND FEEL SP Z O O" and pe.signatures[i].serial=="03:82:cd:4b:6e:d2:1e:d7:c3:ea:ea:26:62:69:d0:00")
}
