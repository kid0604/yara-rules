import "math"

rule WEBSHELL_PHP_OBFUSC
{
	meta:
		description = "PHP webshell obfuscated"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/12"
		modified = "2023-04-05"
		hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
		hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
		hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
		hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
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
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$o1 = "chr(" nocase wide ascii
		$o2 = "chr (" nocase wide ascii
		$o3 = "goto" fullword nocase wide ascii
		$o4 = "\\x9" wide ascii
		$o5 = "\\x3" wide ascii
		$o6 = "\\61" wide ascii
		$o7 = "\\44" wide ascii
		$o8 = "\\112" wide ascii
		$o9 = "\\120" wide ascii
		$fp1 = "$goto" wide ascii
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

	condition:
		not ( any of ($gfp*)) and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and ( not $fp1 and (( filesize <20KB and ((#o1+#o2)>50 or #o3>10 or (#o4+#o5+#o6+#o7+#o8+#o9)>20)) or ( filesize <200KB and ((#o1+#o2)>200 or #o3>30 or (#o4+#o5+#o6+#o7+#o8+#o9)>30)))) and ( any of ($cpayload*) or all of ($m_cpayload_preg_filter*))
}
