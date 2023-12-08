import "math"

rule WEBSHELL_PHP_By_String_Known_Webshell
{
	meta:
		description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021-01-09"
		modified = "2023-04-05"
		score = 70
		hash = "d889da22893536d5965541c30896f4ed4fdf461d"
		hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
		hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
		hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
		hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
		hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
		hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
		hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
		hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
		hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
		hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
		hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
		hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
		hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
		hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
		hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
		hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
		hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
		hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$pbs1 = "b374k shell" wide ascii
		$pbs2 = "b374k/b374k" wide ascii
		$pbs3 = "\"b374k" wide ascii
		$pbs4 = "$b374k(\"" wide ascii
		$pbs5 = "b374k " wide ascii
		$pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
		$pbs7 = "pwnshell" wide ascii
		$pbs8 = "reGeorg" fullword wide ascii
		$pbs9 = "Georg says, 'All seems fine" fullword wide ascii
		$pbs10 = "My PHP Shell - A very simple web shell" wide ascii
		$pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
		$pbs12 = "F4ckTeam" fullword wide ascii
		$pbs15 = "MulCiShell" fullword wide ascii
		$pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
		$pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
		$pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
		$pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
		$pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
		$pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
		$pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
		$pbs52 = "preg_replace(\"/[checksql]/e\""
		$pbs53 = "='http://www.zjjv.com'"
		$pbs54 = "=\"http://www.zjjv.com\""
		$pbs60 = /setting\["AccountType"\]\s?=\s?3/
		$pbs61 = "~+d()\"^\"!{+{}"
		$pbs62 = "use function \\eval as "
		$pbs63 = "use function \\assert as "
		$pbs64 = "eval(`/*" wide ascii
		$pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" wide ascii
		$pbs66 = "Tas9er" fullword wide ascii
		$pbs67 = "\"TSOP_\";" fullword wide ascii
		$pbs68 = "str_rot13('nffreg')" wide ascii
		$pbs69 = "<?=`{$'" wide ascii
		$pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" wide ascii
		$pbs71 = "\"e45e329feb5d925b\"" wide ascii
		$pbs72 = "| PHP FILE MANAGER" wide ascii
		$pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" wide ascii
		$pbs74 = "/*\n\nShellindir.org\n\n*/" wide ascii
		$pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" wide ascii
		$pbs76 = "'password' . '/' . 'id' . '/' . " wide ascii
		$pbs77 = "= create_function /*" wide ascii
		$pbs78 = "W3LL M!N! SH3LL" wide ascii
		$pbs79 = "extract($_REQUEST)&&@$" wide ascii
		$pbs80 = "\"P-h-p-S-p-y\"" wide ascii
		$pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" wide ascii
		$pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" wide ascii
		$pbs83 = "*/base64_decode/*" wide ascii
		$pbs84 = "\n@eval/*" wide ascii
		$pbs85 = "*/eval/*" wide ascii
		$pbs86 = "*/ array /*" wide ascii
		$pbs87 = "2jtffszJe" wide ascii
		$pbs88 = "edocne_46esab" wide ascii
		$pbs89 = "eval($_HEADERS" wide ascii
		$pbs90 = ">Infinity-Sh3ll<" ascii
		$front1 = "<?php eval(" nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }

	condition:
		filesize <1000KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and ( any of ($pbs*) or $front1 in (0..60))
}
