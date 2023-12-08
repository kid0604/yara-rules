rule Windows_Trojan_CobaltStrike_7bcd759c
{
	meta:
		author = "Elastic Security"
		id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
		fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies SSH Agent module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "sshagent.x64.dll" ascii fullword
		$a2 = "sshagent.dll" ascii fullword
		$b1 = "\\\\.\\pipe\\sshagent" ascii fullword
		$b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword

	condition:
		1 of ($a*) and 1 of ($b*)
}
