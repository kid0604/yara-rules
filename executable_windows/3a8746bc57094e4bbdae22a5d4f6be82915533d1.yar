import "pe"

rule Trj_Ponmocup_Downloader
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Ponmocup Downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$vb5 = "VB5" fullword ascii
		$tpb = "www.thepiratebay.org" fullword wide
		$ua = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; SV1)" fullword wide

	condition:
		($mz at 0) and ($vb5) and ($tpb) and ($ua)
}
