import "math"

rule WEBSHELL_PHP_Double_Eval_Tiny_alt_2
{
	meta:
		description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021-01-11"
		modified = "2023-07-05"
		hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
		hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
		hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
		hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
		hash = "006620d2a701de73d995fc950691665c0692af11"
		id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
		$fp1 = "clone" fullword wide ascii
		$fp2 = "* @assert" ascii
		$fp3 = "*@assert" ascii
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
		filesize >70 and filesize <300 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and #payload>=2 and not any of ($fp*)
}
