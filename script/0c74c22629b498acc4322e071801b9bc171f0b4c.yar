rule WEBSHELL_PAS_webshell
{
	meta:
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php"
		$strreplace = "(str_replace("
		$md5 = ".substr(md5(strrev($"
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		( filesize >20KB and filesize <200KB) and all of them
}
