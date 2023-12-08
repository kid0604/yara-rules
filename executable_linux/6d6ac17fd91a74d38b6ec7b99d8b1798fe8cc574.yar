import "pe"

rule LinuxAESDDoS
{
	meta:
		Author = "@benkow_"
		Date = "2014/09/12"
		Description = "Strings inside"
		Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"
		description = "Detects strings inside LinuxAESDDoS malware"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "3AES"
		$b = "Hacker"
		$c = "VERSONEX"

	condition:
		2 of them
}
