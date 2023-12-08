import "math"

rule WEBSHELL_PHP_Includer_Eval
{
	meta:
		description = "PHP webshell which eval()s another included file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/13"
		modified = "2023-04-05"
		hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
		hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
		hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
		hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$payload1 = "eval" fullword wide ascii
		$payload2 = "assert" fullword wide ascii
		$include1 = "$_FILE" wide ascii
		$include2 = "include" wide ascii
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
		filesize <200 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and 1 of ($payload*) and 1 of ($include*)
}
