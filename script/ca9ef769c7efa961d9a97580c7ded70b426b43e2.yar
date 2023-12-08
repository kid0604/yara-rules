import "math"

rule webshell_php_dynamic_big
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 18"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\(base64_decode/ wide ascii
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
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus47 = "Shell" fullword wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus51 = "suhosin" wide ascii
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
		$gen_much_sus78 = "suhosin.executor.disable_" wide ascii
		$gen_much_sus79 = "disabled_suhosin" wide ascii
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
		$gif = { 47 49 46 38 }

	condition:
		filesize <500KB and not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and ( any of ($new_php*) or $php_short at 0) and ( any of ($dynamic*)) and (( filesize >2KB and (math.entropy(500, filesize -500)>=5.7 and math.mean(500, filesize -500)>80 and math.deviation(500, filesize -500,89.0)<23) or (math.entropy(500, filesize -500)>=7.7 and math.mean(500, filesize -500)>120 and math.mean(500, filesize -500)<136 and math.deviation(500, filesize -500,89.0)>65)) or ($gif at 0 or ( filesize <4KB and (1 of ($gen_much_sus*) or 2 of ($gen_bit_sus*))) or ( filesize <20KB and (2 of ($gen_much_sus*) or 3 of ($gen_bit_sus*))) or ( filesize <50KB and (2 of ($gen_much_sus*) or 4 of ($gen_bit_sus*))) or ( filesize <100KB and (2 of ($gen_much_sus*) or 6 of ($gen_bit_sus*))) or ( filesize <150KB and (3 of ($gen_much_sus*) or 7 of ($gen_bit_sus*))) or ( filesize <500KB and (4 of ($gen_much_sus*) or 8 of ($gen_bit_sus*)))))
}
