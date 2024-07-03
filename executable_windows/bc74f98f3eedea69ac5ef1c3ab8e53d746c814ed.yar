rule Windows_Hacktool_EDRrecon_69453aff
{
	meta:
		author = "Elastic Security"
		id = "69453aff-1427-4aae-b1f3-7cce9c93342c"
		fingerprint = "f10758ed032a0f7da0d983839beb12f79fba764aa4ffa0f3716dbfc2e8a3ea82"
		creation_date = "2024-03-07"
		last_modified = "2024-06-10"
		threat_name = "Windows.Hacktool.EDRrecon"
		reference_sample = "f62e51b2405c0d42c53ff1f560376ef0530ba2eea1c97e18f2a3cf148346bcd1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.EDRrecon"
		filetype = "executable"

	strings:
		$s01 = "WdFilter.sys" ascii wide fullword
		$s02 = "mpFilter.sys" ascii wide fullword
		$s03 = "SRTSP.sys" ascii wide fullword
		$s04 = "eeCtrl.sys" ascii wide fullword
		$s05 = "360AvFlt.sys" ascii wide fullword
		$s06 = "360fsflt.sys" ascii wide fullword
		$s07 = "esensor.sys" ascii wide fullword
		$s09 = "klflt.sys" ascii wide fullword
		$s10 = "klam.sys" ascii wide fullword
		$s11 = "SysmonDrv.sys" ascii wide fullword
		$s12 = "CarbonBlackK.sys" ascii wide fullword
		$s13 = "edrsensor.sys" ascii wide fullword
		$s14 = "naswSP.sys" ascii wide fullword
		$s15 = "symevnt.sys" ascii wide fullword
		$s16 = "symevnt32.sys" ascii wide fullword
		$s17 = "CyProtectDrv" ascii wide fullword
		$s18 = "mfeaskm.sys" ascii wide fullword
		$s19 = "SentinelMonitor.sys" ascii wide fullword
		$s20 = "sentinelelam.sys" ascii wide fullword
		$s21 = "SophosSupport.sys" ascii wide fullword
		$s22 = "CSDeviceControl.sys" ascii wide fullword
		$s23 = "csagent.sys" ascii wide fullword
		$s24 = "avgntflt.sys" ascii wide fullword
		$s25 = "bddevflt.sys" ascii wide fullword
		$s26 = "CiscoAMPHeurDriver.sys" ascii wide fullword
		$s27 = "DeepInsFS.sys" ascii wide fullword
		$s28 = "eamonm.sys" ascii wide fullword
		$s29 = "fortirmon.sys" ascii wide fullword
		$s30 = "FlightRecorder.sys" ascii wide fullword
		$s31 = "TmKmSnsr.sys" ascii wide fullword
		$s32 = "cpepmon.sys" ascii wide fullword
		$s33 = "cposfw.sys" ascii wide fullword
		$s34 = "cyvrmtgn.sys" ascii wide fullword
		$s35 = "elastic-endpoint-driver.sys" ascii wide fullword
		$s36 = "elasticelam.sys" ascii wide fullword
		$37 = "mbamwatchdog.sys" ascii wide fullword
		$38 = "FortiEDRWinDriver" ascii wide fullword
		$39 = "QaxNfDrv.sys" ascii wide fullword
		$40 = "qmnetmonw64.sys" ascii wide fullword
		$s41 = "TFsFlt.sys" ascii wide fullword
		$s42 = "DsArk64.sys" ascii wide fullword

	condition:
		14 of them
}
