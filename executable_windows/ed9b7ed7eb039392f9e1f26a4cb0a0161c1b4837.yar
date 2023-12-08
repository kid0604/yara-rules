rule Windows_Trojan_Metasploit_dd5ce989
{
	meta:
		author = "Elastic Security"
		id = "dd5ce989-3925-4e27-97c1-3b8927c557e9"
		fingerprint = "4fc7c309dca197f4626d6dba8afcd576e520dbe2a2dd6f7d38d7ba33ee371d55"
		creation_date = "2021-04-14"
		last_modified = "2021-08-23"
		description = "Identifies Meterpreter DLL used by Metasploit"
		threat_name = "Windows.Trojan.Metasploit"
		reference = "https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/"
		reference_sample = "86cf98bf854b01a55e3f306597437900e11d429ac6b7781e090eeda3a5acb360"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "metsrv.x64.dll" fullword
		$a2 = "metsrv.dll" fullword
		$b1 = "ReflectiveLoader"

	condition:
		1 of ($a*) and 1 of ($b*)
}
