import "pe"

rule skeleton_key_patcher
{
	meta:
		description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$target_process = "lsass.exe" wide
		$dll1 = "cryptdll.dll"
		$dll2 = "samsrv.dll"
		$name = "HookDC.dll"
		$patched1 = "CDLocateCSystem"
		$patched2 = "SamIRetrievePrimaryCredentials"
		$patched3 = "SamIRetrieveMultiplePrimaryCredentials"

	condition:
		all of them
}
