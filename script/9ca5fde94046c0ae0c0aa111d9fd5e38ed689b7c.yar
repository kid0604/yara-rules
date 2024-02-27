import "math"

rule WEBSHELL_PHP_Dynamic_Big_alt_2
{
	meta:
		description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/02/07"
		modified = "2024-02-23"
		score = 50
		hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
		hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
		hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
		hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
		hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
		hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
		hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
		hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
		hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"
		id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
		$new_php2 = "<?php" nocase wide ascii
		$new_php3 = "<script language=\"php" nocase wide ascii
		$php_short = "<?"
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
		$dynamic8 = "eval(" wide ascii
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
		$gen_bit_sus27 = "zuncomp" wide ascii
		$gen_bit_sus28 = "ase6" wide ascii
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
		$gen_bit_sus65 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_bit_sus99 = "$password = " wide ascii
		$gen_bit_sus100 = "();$" wide ascii
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
		$gen_much_sus92 = "DEFACE" fullword wide ascii
		$gen_much_sus93 = "Bypass" fullword wide ascii
		$gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
		$gen_much_sus100 = "rot13" wide ascii
		$gen_much_sus101 = "ini_set('error_log'" wide ascii
		$gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
		$gen_much_sus103 = "=$_COOKIE;" wide ascii
		$gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
		$gen_much_sus105 = "$GLOBALS[\"__" wide ascii
		$gen_much_sus106 = ")-0)" wide ascii
		$gen_much_sus107 = "-0)+" wide ascii
		$gen_much_sus108 = "+0)+" wide ascii
		$gen_much_sus109 = "+(0/" wide ascii
		$gen_much_sus110 = "+(0+" wide ascii
		$gen_much_sus111 = "extract($_REQUEST)" wide ascii
		$gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
		$gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
		$gen_much_sus114 = "\" .\"" wide ascii
		$gen_much_sus115 = "end($_POST" wide ascii
		$weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
		$weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii
		$weevely3 = /';\$\w{1,2}='/ wide ascii
		$weevely4 = "str_replace" fullword wide ascii
		$gif = { 47 49 46 38 }
		$fp1 = "# Some examples from obfuscated malware:" ascii
		$fp2 = "* @package   PHP_CodeSniffer" ascii
		$fp3 = ".jQuery===" ascii
		$fp4 = "* @param string $lstat encoded LStat string" ascii

	condition:
		not ( uint16(0)==0x5a4d or uint32be(0)==0x3c3f786d or uint32be(0)==0x3c3f584d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50 or 1 of ($fp*)) and ( any of ($new_php*) or $php_short at 0) and ( any of ($dynamic*)) and ($gif at 0 or (( filesize <1KB and (1 of ($gen_much_sus*))) or ( filesize <2KB and ((#weevely1+#weevely2+#weevely3)>2 and #weevely4>1)) or ( filesize <4000 and (1 of ($gen_much_sus*) or 2 of ($gen_bit_sus*))) or ( filesize <20KB and (2 of ($gen_much_sus*) or 4 of ($gen_bit_sus*))) or ( filesize <50KB and (3 of ($gen_much_sus*) or 5 of ($gen_bit_sus*))) or ( filesize <100KB and (3 of ($gen_much_sus*) or 6 of ($gen_bit_sus*))) or ( filesize <160KB and (3 of ($gen_much_sus*) or 7 of ($gen_bit_sus*) or (math.deviation(500, filesize -500,89.0)>70))) or ( filesize <500KB and (4 of ($gen_much_sus*) or 8 of ($gen_bit_sus*) or #gen_much_sus104>4))) or ( filesize >2KB and filesize <1MB and ((math.entropy(500, filesize -500)>=5.7 and math.mean(500, filesize -500)>80 and math.deviation(500, filesize -500,89.0)<23) or (math.entropy(500, filesize -500)>=7.7 and math.mean(500, filesize -500)>120 and math.mean(500, filesize -500)<136 and math.deviation(500, filesize -500,89.0)>65))))
}
