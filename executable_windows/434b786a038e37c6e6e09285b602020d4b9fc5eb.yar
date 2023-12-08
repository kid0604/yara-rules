import "pe"

rule Trj_Elex_Installer_NSIS
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Installer NSIS"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$str1 = {4e 75 6c 6c 73 6f 66 74 }
		$str2 = {b7 a2 d5 dc 0c d6 a6 3a}

	condition:
		($mz at 0) and ($str1 at 0xA008) and ($str2 at 0x1c8700)
}
