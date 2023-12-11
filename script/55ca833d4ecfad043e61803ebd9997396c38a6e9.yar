import "math"

rule WEBSHELL_PHP_Includer_Tiny
{
	meta:
		description = "Suspicious: Might be PHP webshell includer, check the included file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/17"
		modified = "2023-0/-05"
		hash = "0687585025f99596508783b891e26d6989eec2ba"
		hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
		hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii
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
		filesize <100 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and any of ($php_include*)
}
