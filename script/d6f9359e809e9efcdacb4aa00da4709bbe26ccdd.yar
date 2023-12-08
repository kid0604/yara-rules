rule ps1_toolkit_Inveigh_BruteForce_3
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
		$s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
		$s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
		$s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
		$s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
		$s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
		$s7 = "}.bruteforce_running)" ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
