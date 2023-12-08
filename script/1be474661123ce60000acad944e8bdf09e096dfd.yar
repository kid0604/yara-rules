import "math"

rule webshell_php_strings_susp
{
	meta:
		description = "Detect the risk of malicious file (phpwebshell)  Rule 24"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sstring1 = "eval(\"?>\"" nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
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

	condition:
		filesize <700KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and not ( any of ($gfp*)) and (2 of ($sstring*) or (1 of ($sstring*) and ( any of ($inp*))))
}
