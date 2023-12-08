import "pe"

rule APT_MAL_NK_3CX_macOS_Elextron_App_Mar23_1
{
	meta:
		description = "Detects macOS malware used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-03-31"
		score = 80
		hash1 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		hash2 = "f7ba7f9bf608128894196cf7314f68b78d2a6df10718c8e0cd64dbe3b86bc730"
		os = "macos"
		filetype = "executable"

	strings:
		$a1 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
		$a2 = "com.electron.3cx-desktop-app" ascii fullword
		$s1 = "s8T/RXMlALbXfowom9qk15FgtdI=" ascii
		$s2 = "o8NQKPJE6voVZUIGtXihq7lp0cY=" ascii

	condition:
		uint16(0)==0xfacf and filesize <400KB and ( all of ($a*) and 1 of ($s*))
}
