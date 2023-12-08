import "math"

rule WEBSHELL_PHP_OBFUSC_3
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/04/17"
		modified = "2023-07-05"
		hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
		hash = "d6b851cae249ea6744078393f622ace15f9880bc"
		hash = "14e02b61905cf373ba9234a13958310652a91ece"
		hash = "6f97f607a3db798128288e32de851c6f56e91c1d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$obf1 = "chr(" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$callback1 = /\bob_start[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback4 = /\barray_filter[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback7 = /\barray_map[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback8 = /\barray_reduce[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback11 = /\barray_udiff[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback14 = /\barray_uintersect[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback16 = /\barray_walk[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback17 = /\bassert_options[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback18 = /\buasort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback19 = /\buksort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback20 = /\busort[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback23 = /\biterator_apply[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback24 = /\bcall_user_func[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback28 = /\bset_error_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
		$cfp3 = "<?phpclass WPML" ascii
		$cpayload1 = /\beval[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload2 = /\bexec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload4 = /\bpassthru[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload5 = /\bsystem[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload6 = /\bpopen[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload7 = /\bproc_open[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload9 = /\bassert[\n\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\n\t ]*(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\n\t ]*(\([^)]|\/\*)/ nocase wide ascii
		$cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]*[,}\)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]*(\([^\)]|\/\*)/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		$cobfs1 = "gzinflate" fullword nocase wide ascii
		$cobfs2 = "gzuncompress" fullword nocase wide ascii
		$cobfs3 = "gzdecode" fullword nocase wide ascii
		$cobfs4 = "base64_decode" fullword nocase wide ascii
		$cobfs5 = "pack" fullword nocase wide ascii
		$cobfs6 = "undecode" fullword nocase wide ascii
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = "self.delete"
		$gen_bit_sus9 = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7 = "Web Shell" nocase
		$gen_much_sus8 = "WebShell" nocase
		$gen_much_sus3 = "hidded shell"
		$gen_much_sus4 = "WScript.Shell.1" nocase
		$gen_much_sus5 = "AspExec"
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang"
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821 = "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
		$gen_much_sus93 = "eval(\"/*" wide ascii
		$gen_much_sus94 = "=$_COOKIE;" wide ascii
		$gif = { 47 49 46 38 }

	condition:
		((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and (( not any of ($cfp*) and ( any of ($callback*) or all of ($m_callback*))) or ( any of ($cpayload*) or all of ($m_cpayload_preg_filter*))) and ( any of ($cobfs*)) and ( filesize <1KB or ( filesize <3KB and (($gif at 0 or ( filesize <4KB and (1 of ($gen_much_sus*) or 2 of ($gen_bit_sus*))) or ( filesize <20KB and (2 of ($gen_much_sus*) or 3 of ($gen_bit_sus*))) or ( filesize <50KB and (2 of ($gen_much_sus*) or 4 of ($gen_bit_sus*))) or ( filesize <100KB and (2 of ($gen_much_sus*) or 6 of ($gen_bit_sus*))) or ( filesize <150KB and (3 of ($gen_much_sus*) or 7 of ($gen_bit_sus*))) or ( filesize <500KB and (4 of ($gen_much_sus*) or 8 of ($gen_bit_sus*)))) or #obf1>10)))
}
