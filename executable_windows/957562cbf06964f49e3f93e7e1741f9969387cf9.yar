import "pe"

rule SplashBitmapv100WithUnpackCodeBoBBobsoft
{
	meta:
		author = "malware-lu"
		description = "Detects the SplashBitmapv1.00 malware with unpacking code from BoBBobsoft"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED [4] 8D BD [4] 8D 8D [4] 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 [4] 6A 40 }

	condition:
		$a0 at pe.entry_point
}
