rule GlassRAT_Generic
{
	meta:
		description = "Detects GlassRAT Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/peering-into-glassrat/"
		date = "2015-11-23"
		score = 80
		hash1 = "30d26aebcee21e4811ff3a44a7198a5c519843a24f334880384a7158e07ae399"
		hash2 = "3bdeb3805e9230361fb93c6ffb0bfec8d3aee9455d95b2428c7f6292d387d3a4"
		hash3 = "79993f1912958078c4d98503e00dc526eb1d0ca4d020d17b010efa6c515ca92e"
		hash4 = "a9b30b928ebf9cda5136ee37053fa045f3a53d0706dcb2343c91013193de761e"
		hash5 = "c11faf7290299bb13925e46d040ed59ab3ca8938eab1f171aa452603602155cb"
		hash6 = "d95fa58a81ab2d90a8cbe05165c00f9c8ad5b4f49e98df2ad391f5586893490d"
		hash7 = "f1209eb95ce1319af61f371c7f27bf6846eb90f8fd19e8d84110ebaf4744b6ea"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe /c %s" fullword ascii
		$s2 = "update.dll" fullword ascii
		$s3 = "SYSTEM\\CurrentControlSet\\Services\\RasAuto\\Parameters" fullword ascii
		$s4 = "%%temp%%\\%u" fullword ascii
		$s5 = "\\off.dat" ascii
		$s6 = "rundll32 \"%s\",AddNum" fullword ascii
		$s7 = "cmd.exe /c erase /F \"%s\"" fullword ascii
		$s8 = "SYSTEM\\ControlSet00%d\\Services\\RasAuto" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <15MB and 5 of them
}
