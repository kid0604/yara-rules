rule EXPL_Exploit_TLB_Scripts
{
	meta:
		description = "Detects malicious TLB files which may be delivered via Visual Studio projects"
		author = "Rich Warren (slightly modified by Florian Roth)"
		reference = "https://github.com/outflanknl/Presentations/blob/master/Nullcon2020_COM-promise_-_Attacking_Windows_development_environments.pdf"
		date = "2021-01-26"
		os = "windows"
		filetype = "script"

	strings:
		$a = ".sct" ascii nocase
		$b = "script:" ascii nocase
		$c = "scriptlet:" ascii nocase
		$d = "soap:" ascii nocase
		$e = "winmgmts:" ascii nocase

	condition:
		uint32be(0)==0x4D534654 and filesize <100KB and any of them
}
