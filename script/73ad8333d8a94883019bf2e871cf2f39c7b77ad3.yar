import "math"

rule WEBSHELL_PHP_OBFUSC_Fopo
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
		hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
		hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
		date = "2021/01/12"
		modified = "2023-04-05"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$payload = /(\beval[\t ]*\([^)]|\bassert[\t ]*\([^)])/ nocase wide ascii
		$one1 = "7QGV2YWwo" wide ascii
		$one2 = "tAZXZhbC" wide ascii
		$one3 = "O0BldmFsK" wide ascii
		$one4 = "sAQABlAHYAYQBsACgA" wide ascii
		$one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
		$one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
		$two1 = "7QGFzc2VydC" wide ascii
		$two2 = "tAYXNzZXJ0K" wide ascii
		$two3 = "O0Bhc3NlcnQo" wide ascii
		$two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
		$two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
		$two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

	condition:
		filesize <3000KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and $payload and ( any of ($one*) or any of ($two*))
}
