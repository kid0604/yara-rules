import "pe"

rule INDICATOR_KB_CERT_044e05bb1a01a1cbb50cfb6cd24e5d6b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "149b7bbe88d4754f2900c88516ce97be605553ff"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and pe.signatures[i].serial=="04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b")
}
