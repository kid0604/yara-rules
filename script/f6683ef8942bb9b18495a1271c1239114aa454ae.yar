rule CobaltStrike_Resources_Template_x86_Vba_v3_8_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.x86.vba signature for versions v3.8 to v4.x"
		hash = "fc66cb120e7bc9209882620f5df7fdf45394c44ca71701a8662210cf3a40e142"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
		$allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
		$writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
		$runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
		$vars = "Dim rwxpage As Long" nocase
		$res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
		$rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"

	condition:
		all of them and @vars[1]<@res[1] and @allocstuff[1]<@rwxpage[1]
}
