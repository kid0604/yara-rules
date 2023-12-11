import "pe"

rule Trj_Elex_Dll32
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex DLL 32 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$str1 = {59 00 72 00 72 00 65 00 68 00 73 00}
		$str2 = "RookIE/1.0"

	condition:
		(pe.machine==pe.MACHINE_I386) and (pe.characteristics&pe.DLL) and ($mz at 0) and ($str1) and ($str2)
}
