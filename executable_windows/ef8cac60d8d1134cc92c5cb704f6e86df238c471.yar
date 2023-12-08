rule Windows_Ransomware_Sodinokibi_182b2cea : beta
{
	meta:
		author = "Elastic Security"
		id = "182b2cea-5aae-443a-9a2e-b3121a0ac8c7"
		fingerprint = "b71d862f6d45b388a106bf694e2bf5b4e4d78649c396e89bda46eab4206339fe"
		creation_date = "2020-06-18"
		last_modified = "2021-10-04"
		description = "Identifies SODINOKIBI/REvil ransomware"
		threat_name = "Windows.Ransomware.Sodinokibi"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "expand 32-byte kexpand 16-byte k" ascii fullword
		$b1 = "ServicesActive" wide fullword
		$b2 = "CreateThread" ascii fullword
		$b3 = "GetExitCodeProcess" ascii fullword
		$b4 = "CloseHandle" ascii fullword
		$b5 = "SetErrorMode" ascii fullword
		$b6 = ":!:(:/:6:C:\\:m:" ascii fullword

	condition:
		($a1 and 6 of ($b*))
}
