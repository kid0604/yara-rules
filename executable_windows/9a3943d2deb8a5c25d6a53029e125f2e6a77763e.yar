rule Msfpayloads_msf_exe_2
{
	meta:
		description = "Metasploit Payloads - file msf-exe.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "= new System.Diagnostics.Process();" fullword ascii
		$x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
		$x3 = ", \"svchost.exe\");" ascii
		$s4 = " = Path.GetTempPath();" ascii

	condition:
		all of them
}
