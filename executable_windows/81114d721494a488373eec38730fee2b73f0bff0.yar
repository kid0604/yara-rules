import "pe"

rule GoldDragon_RunnignRAT
{
	meta:
		description = "Detects Running RAT malware from Gold Dragon report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/rW1yvZ"
		date = "2018-02-03"
		modified = "2023-01-07"
		hash1 = "94aa827a514d7aa70c404ec326edaaad4b2b738ffaea5a66c0c9f246738df579"
		hash2 = "5cbc07895d099ce39a3142025c557b7fac41d79914535ab7ffc2094809f12a4b"
		hash3 = "98ccf3a463b81a47fdf4275e228a8f2266e613e08baae8bdcd098e49851ed49a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe /c systeminfo " fullword ascii
		$s2 = "ieproxy.dll" fullword ascii
		$s3 = "taskkill /f /im daumcleaner.exe" fullword ascii
		$s4 = "cmd.exe /c tasklist " fullword ascii
		$s5 = "rundll32.exe \"%s\" Run" fullword ascii
		$s6 = "Mozilla/5.0 (Windows NT 5.2; rv:12.0) Gecko/20100101 Firefox/12.0" fullword ascii
		$s7 = "%s\\%s_%03d" fullword wide
		$s8 = "\\PI_001.dat" ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (3 of them )
}
