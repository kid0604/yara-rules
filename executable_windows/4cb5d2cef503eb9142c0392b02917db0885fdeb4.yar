rule Windows_Trojan_MicroBackdoor_46f2e5fd
{
	meta:
		author = "Elastic Security"
		id = "46f2e5fd-edea-4321-b38c-7478b47f054b"
		fingerprint = "d4e410b9c36c1d5206f5d17190ef4e5fd4b4e4d40acad703775aed085a08ef7c"
		creation_date = "2022-03-07"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.MicroBackdoor"
		reference_sample = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan MicroBackdoor"
		filetype = "executable"

	strings:
		$a1 = "cmd.exe /C \"%s%s\"" wide fullword
		$a2 = "%s|%s|%d|%s|%d|%d" wide fullword
		$a3 = "{{{$%.8x}}}" ascii fullword
		$a4 = "30D78F9B-C56E-472C-8A29-E9F27FD8C985" ascii fullword
		$a5 = "chcp 65001 > NUL & " wide fullword
		$a6 = "CONNECT %s:%d HTTP/1.0" ascii fullword

	condition:
		5 of them
}
