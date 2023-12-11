import "math"

rule webshell_php_generic_callback
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$gfp1 = "eval(\"return [$serialised_parameter"
		$gfp2 = "$this->assert(strpos($styles, $"
		$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5 = "$_POST[partition_by]($_POST["
		$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7 = "The above example code can be easily exploited by passing in a string such as"
		$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$gfp_tiny3 = "include \"./common.php\";"
		$gfp_tiny4 = "assert('FALSE');"
		$gfp_tiny5 = "assert(false);"
		$gfp_tiny6 = "assert(FALSE);"
		$gfp_tiny7 = "assert('array_key_exists("
		$gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
		$gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
		$gfp_tiny10 = "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$callback1 = /\bob_start[\t ]*\([^)]/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback4 = /\barray_filter[\t ]*\([^)]/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\t ]*\([^)]/ nocase wide ascii
		$callback7 = /\barray_map[\t ]*\([^)]/ nocase wide ascii
		$callback8 = /\barray_reduce[\t ]*\([^)]/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback11 = /\barray_udiff[\t ]*\([^)]/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\t ]*\([^)]/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\t ]*\([^)]/ nocase wide ascii
		$callback14 = /\barray_uintersect[\t ]*\([^)]/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\t ]*\([^)]/ nocase wide ascii
		$callback16 = /\barray_walk[\t ]*\([^)]/ nocase wide ascii
		$callback17 = /\bassert_options[\t ]*\([^)]/ nocase wide ascii
		$callback18 = /\buasort[\t ]*\([^)]/ nocase wide ascii
		$callback19 = /\buksort[\t ]*\([^)]/ nocase wide ascii
		$callback20 = /\busort[\t ]*\([^)]/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\t ]*\([^)]/ nocase wide ascii
		$callback23 = /\biterator_apply[\t ]*\([^)]/ nocase wide ascii
		$callback24 = /\bcall_user_func[\t ]*\([^)]/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\t ]*\([^)]/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\t ]*\([^)]/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\t ]*\([^)]/ nocase wide ascii
		$callback28 = /\bset_error_handler[\t ]*\([^)]/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\t ]*\([^)]/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\t ]*\([^)]/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\t ]*\([^)]/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\t ]*\([^)]/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\t ]*\([^)]/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\t ]*\([^)]/ nocase wide ascii
		$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
		$cfp3 = "<?phpclass WPML" ascii
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
		not ( any of ($gfp*)) and not ( any of ($gfp_tiny*)) and ( any of ($inp*)) and ( not any of ($cfp*) and ( any of ($callback*) or all of ($m_callback*))) and ( filesize <1000 or ($gif at 0 or ( filesize <4KB and (1 of ($gen_much_sus*) or 2 of ($gen_bit_sus*))) or ( filesize <20KB and (2 of ($gen_much_sus*) or 3 of ($gen_bit_sus*))) or ( filesize <50KB and (2 of ($gen_much_sus*) or 4 of ($gen_bit_sus*))) or ( filesize <100KB and (2 of ($gen_much_sus*) or 6 of ($gen_bit_sus*))) or ( filesize <150KB and (3 of ($gen_much_sus*) or 7 of ($gen_bit_sus*))) or ( filesize <500KB and (4 of ($gen_much_sus*) or 8 of ($gen_bit_sus*)))))
}
