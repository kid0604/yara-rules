rule Sofacy_CollectorStealer_Gen3
{
	meta:
		description = "File collectors / USB stealers - Generic"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NvCpld.dll" fullword ascii
		$s4 = "NvStart" fullword ascii
		$s5 = "NvStop" fullword ascii
		$a1 = "%.4d%.2d%.2d%.2d%.2d%.2d%.2d%.4d" fullword wide
		$a2 = "IGFSRVC.dll" fullword wide
		$a3 = "Common User Interface" fullword wide
		$a4 = "igfsrvc Module" fullword wide
		$b1 = " Operating System                        " fullword wide
		$b2 = "Microsoft Corporation                                       " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and ( all of ($s*) and ( all of ($a*) or all of ($b*)))
}
