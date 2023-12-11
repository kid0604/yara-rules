rule HYTop2006_rar_Folder_2006X_alt_1
{
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
		$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""

	condition:
		all of them
}
