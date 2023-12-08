rule webshell_webshells_new_code
{
	meta:
		description = "Web shells - generated from file code.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "a444014c134ff24c0be5a05c02b81a79"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
		$s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
		$s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
		$s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
		$s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"

	condition:
		1 of them
}
