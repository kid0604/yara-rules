rule phpshell_3
{
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
		$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"

	condition:
		all of them
}
