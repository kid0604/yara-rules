import "pe"

rule INDICATOR_KB_CERT_01ea62e443cb2250c870ff6bb13ba98e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f293eed3ff3d548262cddc43dce58cfc7f763622"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tencent Technology(Shenzhen) Company Limited" and pe.signatures[i].serial=="01:ea:62:e4:43:cb:22:50:c8:70:ff:6b:b1:3b:a9:8e")
}
