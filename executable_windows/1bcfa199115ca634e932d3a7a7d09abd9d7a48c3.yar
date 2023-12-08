import "pe"

rule EYouDiDaiYueHeiFengGao
{
	meta:
		author = "malware-lu"
		description = "Detects the EYouDiDaiYueHeiFengGao malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B8 [4] E8 [4] 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 [4] 0F 6E C0 B8 [4] 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 [5] FF E0 }

	condition:
		$a0 at pe.entry_point
}
