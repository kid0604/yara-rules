import "pe"

rule INDICATOR_KB_CERT_d0b094274c761f367a8eaea08e1d9c8f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e94a9d81c4a67ef953fdb27aad6ec8fa347e6903b140d21468066bdca8925bc5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nsasoft US LLC" and pe.signatures[i].serial=="d0:b0:94:27:4c:76:1f:36:7a:8e:ae:a0:8e:1d:9c:8f")
}
