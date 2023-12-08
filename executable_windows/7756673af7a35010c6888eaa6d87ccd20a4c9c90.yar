rule Windows_Ransomware_Ryuk_8ba51798 : beta
{
	meta:
		author = "Elastic Security"
		id = "8ba51798-15d7-4f02-97fa-1844465ae9d8"
		fingerprint = "8e284bc6015502577a6ddd140b9cd110fd44d4d2cb55d0fdec5bebf3356fd7b3"
		creation_date = "2020-04-30"
		last_modified = "2021-08-23"
		description = "Identifies RYUK ransomware"
		threat_name = "Windows.Ransomware.Ryuk"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "/v \"svchos\" /f" wide fullword
		$c2 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii fullword
		$c3 = "lsaas.exe" wide fullword
		$c4 = "FA_Scheduler" wide fullword
		$c5 = "ocautoupds" wide fullword
		$c6 = "CNTAoSMgr" wide fullword
		$c7 = "hrmlog" wide fullword
		$c8 = "UNIQUE_ID_DO_NOT_REMOVE" wide fullword

	condition:
		3 of ($c*)
}
