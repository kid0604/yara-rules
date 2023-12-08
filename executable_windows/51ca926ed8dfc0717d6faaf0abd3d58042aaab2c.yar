import "pe"

rule INDICATOR_KB_CERT_118d813d830f218c0f46d4fc
{
	meta:
		author = "ditekSHen"
		description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
		thumbprint = "bd16f70bf6c2ef330c5a4f3a27856a0d030d77fa"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shang Hai Shen Wei Wang Luo Ke Ji You Xian Gong Si" and pe.signatures[i].serial=="11:8d:81:3d:83:0f:21:8c:0f:46:d4:fc")
}
