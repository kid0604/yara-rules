rule lamashell_php
{
	meta:
		description = "Semi-Auto-generated  - file lamashell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "de9abc2e38420cad729648e93dfc6687"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "lama's'hell" fullword
		$s1 = "if($_POST['king'] == \"\") {"
		$s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"

	condition:
		1 of them
}
