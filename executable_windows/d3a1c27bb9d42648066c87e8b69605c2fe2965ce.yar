import "pe"

rule APT_SUSP_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects indicator (event name) found in samples related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		date = "2023-03-30"
		score = 70
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "AVMonitorRefreshEvent" wide fullword

	condition:
		1 of them
}
