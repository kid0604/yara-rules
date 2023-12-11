rule shelltools_g0t_root_HideRun
{
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."

	condition:
		all of them
}
