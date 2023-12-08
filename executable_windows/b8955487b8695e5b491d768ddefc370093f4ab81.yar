rule hxdef100_2
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
		$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
		$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"

	condition:
		all of them
}
