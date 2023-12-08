import "math"

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex
{
	meta:
		description = "PHP webshell obfuscated by encoding of mixed hex and dec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/18"
		modified = "2023-04-05"
		hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
		hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
		hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
		hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
		hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
		hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
		hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
		hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
		hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
		hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
		hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
		hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
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
		filesize <700KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and any of ($mix*)
}
