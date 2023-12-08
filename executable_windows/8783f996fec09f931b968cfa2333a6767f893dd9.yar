rule Mithril_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "017191562d72ab0ca551eb89256650bd"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"

	condition:
		all of them
}
