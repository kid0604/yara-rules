rule EXPL_Cleo_Exploitation_Log_Indicators_Dec24 : SCRIPT
{
	meta:
		description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
		date = "2024-12-10"
		score = 75
		id = "385042a9-fc8c-5b50-975f-3436a16e6861"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Note: Processing autorun file 'autorun\\health" ascii wide
		$x2 = "60282967-dc91-40ef-a34c-38e992509c2c.xml" ascii wide
		$x3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide

	condition:
		1 of them
}
