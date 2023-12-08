rule PAS_TOOL_PHP_WEB_KIT_mod
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
		author = "US CERT - modified by Florian Roth due to performance reasons"
		date = "2016/12/29"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php = "<?php"
		$base64decode1 = "='base'.("
		$strreplace = "str_replace(\"\\n\", ''"
		$md5 = ".substr(md5(strrev("
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		uint32(0)==0x68703f3c and $php at 0 and ( filesize >10KB and filesize <30KB) and #cookie==2 and #isset==3 and all of them
}
