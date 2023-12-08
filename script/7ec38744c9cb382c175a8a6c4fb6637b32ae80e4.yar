rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1
{
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "f3ca29b7999643507081caab926e2e74"
		hash2 = "527cf81f9272919bf872007e21c4bdda"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
		$s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
		$s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
		$s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword

	condition:
		2 of them
}
