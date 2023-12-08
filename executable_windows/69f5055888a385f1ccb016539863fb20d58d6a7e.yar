import "pe"

rule Trj_Ponmocup_dll
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Bot DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$pck = { 00 81 23 00 33 3E 00 00 3B F4 56 00 00 00 7D 00 }
		$upk = { 68 F4 14 00 10 A1 6C C0 02 10 FF D0 59 59 E9 7A }

	condition:
		($mz at 0) and ($pck at 0x8a50) and ($upk at 0x61f)
}
