rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9
{
	meta:
		description = "Detects a PHP web shell upload command"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}"

	condition:
		any of them
}
