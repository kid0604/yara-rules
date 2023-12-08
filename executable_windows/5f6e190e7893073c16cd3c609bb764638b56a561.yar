rule BluesPortScan
{
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"

	condition:
		all of them
}
