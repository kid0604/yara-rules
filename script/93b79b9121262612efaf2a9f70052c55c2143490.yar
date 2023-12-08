rule webshell_php_backdoor
{
	meta:
		description = "Web Shell - file php-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
		$s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "

	condition:
		all of them
}
