import "pe"

rule Trj_Ponmocup
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Installer"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$pac = { 48 8F BB 54 5F 3E 4F 4E }
		$unp = { 8B B8 7C 1F 46 00 33 C8 }

	condition:
		($mz at 0) and ($pac at 0x61F7C) and ($unp at 0x29F0)
}
