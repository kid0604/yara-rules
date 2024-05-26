import "math"

rule WEBSHELL_PHP_Generic_Backticks_alt_2
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
		hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
		hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$backtick = /`\s*\{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii
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
		((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and $backtick and filesize <200
}
