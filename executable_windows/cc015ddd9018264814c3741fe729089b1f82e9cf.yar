rule Windows_Trojan_CobaltStrike_a3fb2616
{
	meta:
		author = "Elastic Security"
		id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
		fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for browser pivot "
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "browserpivot.dll" ascii fullword
		$a2 = "browserpivot.x64.dll" ascii fullword
		$b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
		$b2 = "COBALTSTRIKE" ascii fullword

	condition:
		1 of ($a*) and 2 of ($b*)
}
