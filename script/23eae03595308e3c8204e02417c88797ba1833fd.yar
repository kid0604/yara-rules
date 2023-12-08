import "math"

rule webshell_php_obfuscated_tiny
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 10"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$obf1 = /\w'\.'\w/ wide ascii
		$obf2 = /\w\"\.\"\w/ wide ascii
		$obf3 = "].$" wide ascii
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
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii

	condition:
		filesize <500 and not ( any of ($gfp*)) and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and ( any of ($cpayload*) or all of ($m_cpayload_preg_filter*)) and ((#obf1+#obf2)>2 or #obf3>10)
}
