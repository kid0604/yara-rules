rule CN_Honker_Webshell_ASPX_aspx3
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dd61481771f67d9593214e605e63b62d5400c72f"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii
		$s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii

	condition:
		filesize <100KB and all of them
}
