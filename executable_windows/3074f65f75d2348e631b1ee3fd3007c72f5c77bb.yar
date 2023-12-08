rule byshell063_ntboot
{
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"

	condition:
		all of them
}
