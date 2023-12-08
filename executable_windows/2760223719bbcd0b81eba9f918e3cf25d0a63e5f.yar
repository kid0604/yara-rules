import "pe"

rule ThemidaWinLicenseV1XNoCompressionSecureEngineOreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida-protected Windows executables with a specific version and no compression using SecureEngine by Oreans Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED [4] 89 95 [4] 89 B5 [4] 89 85 [4] 83 BD [5] 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 [4] 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}
