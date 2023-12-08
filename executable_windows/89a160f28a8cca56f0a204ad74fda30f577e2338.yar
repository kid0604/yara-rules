import "pe"

rule Trj_Elex_Service32
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		description = "Elex Service 32 bits"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$str1 = "http://xa.xingcloud.com/v4/sof-everything/"
		$str2 = "http://www.mysearch123.com"
		$str3 = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma"

	condition:
		(pe.machine==pe.MACHINE_I386) and ($mz at 0) and ($str1) and ($str2) and ($str3)
}
