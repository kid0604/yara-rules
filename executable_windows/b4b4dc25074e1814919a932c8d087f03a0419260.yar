import "pe"

rule INDICATOR_KB_CERT_08653ef2ed9e6ebb56ffa7e93f963235
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1567d022b47704a1fd7ab71ff60a121d0c1df33a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Haw Farm LIMITED" and pe.signatures[i].serial=="08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35")
}
