import "math"

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC_alt_2
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
		hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
		hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = /echo[\t ]{0,500}\(?`\$/ wide ascii
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
		filesize <500 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and $s1
}
