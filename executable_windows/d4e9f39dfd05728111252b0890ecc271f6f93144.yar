rule hxdef100
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "RtlAnsiStringToUnicodeString"
		$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
		$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"

	condition:
		all of them
}
