rule StealthWasp_s_Basic_PortScanner_v1_2
{
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"

	condition:
		all of them
}
