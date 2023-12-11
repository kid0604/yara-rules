import "pe"

rule INDICATOR_KB_CERT_5fbf16a33d26390a15f046c310030cf0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "61f422db86bbc5093b1466a281f13346f8d81792"
		hash1 = "f45e5f160a6de454d1db21b599843637103506545183a30053d03b609f92bbdc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and pe.signatures[i].serial=="5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0")
}
