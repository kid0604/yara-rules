rule PowerShell_Susp_Parameter_Combo : HIGHVOL FILE
{
	meta:
		description = "Detects PowerShell invocation with suspicious parameters"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/uAic1X"
		date = "2017-03-12"
		modified = "2022-09-15"
		score = 60
		os = "windows"
		filetype = "script"

	strings:
		$sa1 = " -enc " ascii wide nocase
		$sa2 = " -EncodedCommand " ascii wide nocase
		$sa3 = " /enc " ascii wide nocase
		$sa4 = " /EncodedCommand " ascii wide nocase
		$sb1 = " -w hidden " ascii wide nocase
		$sb2 = " -window hidden " ascii wide nocase
		$sb3 = " -windowstyle hidden " ascii wide nocase
		$sb4 = " /w hidden " ascii wide nocase
		$sb5 = " /window hidden " ascii wide nocase
		$sb6 = " /windowstyle hidden " ascii wide nocase
		$sc1 = " -nop " ascii wide nocase
		$sc2 = " -noprofile " ascii wide nocase
		$sc3 = " /nop " ascii wide nocase
		$sc4 = " /noprofile " ascii wide nocase
		$sd1 = " -noni " ascii wide nocase
		$sd2 = " -noninteractive " ascii wide nocase
		$sd3 = " /noni " ascii wide nocase
		$sd4 = " /noninteractive " ascii wide nocase
		$se1 = " -ep bypass " ascii wide nocase
		$se2 = " -exec bypass " ascii wide nocase
		$se3 = " -executionpolicy bypass " ascii wide nocase
		$se4 = " -exec bypass " ascii wide nocase
		$se5 = " /ep bypass " ascii wide nocase
		$se6 = " /exec bypass " ascii wide nocase
		$se7 = " /executionpolicy bypass " ascii wide nocase
		$se8 = " /exec bypass " ascii wide nocase
		$sf1 = " -sta " ascii wide
		$sf2 = " /sta " ascii wide
		$fp1 = "Chocolatey Software" ascii wide
		$fp2 = "VBOX_MSI_INSTALL_PATH" ascii wide
		$fp3 = "\\Local\\Temp\\en-US.ps1" ascii wide
		$fp4 = "Lenovo Vantage - Battery Gauge Helper" wide fullword
		$fp5 = "\\LastPass\\lpwinmetro\\AppxUpgradeUwp.ps1" ascii
		$fp6 = "# use the encoded form to mitigate quoting complications that full scriptblock transfer exposes" ascii
		$fp7 = "Write-AnsibleLog \"INFO - s" ascii
		$fp8 = "\\Packages\\Matrix42\\" ascii
		$fp9 = "echo " ascii
		$fp10 = "install" ascii fullword
		$fp11 = "REM " ascii
		$fp12 = "set /p " ascii
		$fp13 = "rxScan Application" wide
		$fpa1 = "All Rights"
		$fpa2 = "<html"
		$fpa2b = "<HTML"
		$fpa3 = "Copyright"
		$fpa4 = "License"
		$fpa5 = "<?xml"
		$fpa6 = "Help" fullword
		$fpa7 = "COPYRIGHT"

	condition:
		filesize <3000KB and 4 of ($s*) and not 1 of ($fp*) and uint32be(0)!=0x456C6646
}
