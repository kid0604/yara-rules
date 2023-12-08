rule Simple_PHP_BackDooR
{
	meta:
		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a401132363eecc3a1040774bec9cb24f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
		$s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
		$s9 = "// a simple php backdoor"

	condition:
		1 of them
}
