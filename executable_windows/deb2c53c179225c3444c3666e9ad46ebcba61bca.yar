rule Casper_EXE_Dropper
{
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/05"
		hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "<Command>" fullword ascii
		$s1 = "</Command>" fullword ascii
		$s2 = "\" /d \"" fullword ascii
		$s4 = "'%s' %s" fullword ascii
		$s5 = "nKERNEL32.DLL" fullword wide
		$s6 = "@ReturnValue" fullword wide
		$s7 = "ID: 0x%x" fullword ascii
		$s8 = "Name: %S" fullword ascii

	condition:
		7 of them
}
