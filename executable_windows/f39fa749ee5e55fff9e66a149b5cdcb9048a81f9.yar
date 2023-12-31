rule IronGate_APT_Step7ProSim_Gen
{
	meta:
		description = "Detects IronGate APT Malware - Step7ProSim DLL"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "0539af1a0cc7f231af8f135920a990321529479f6534c3b64e571d490e1514c3"
		hash2 = "fa8400422f3161206814590768fc1a27cf6420fc5d322d52e82899ac9f49e14f"
		hash3 = "5ab1672b15de9bda84298e0bb226265af09b70a9f0b26d6dfb7bdd6cbaed192d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\obj\\Release\\Step7ProSim.pdb" ascii
		$s1 = "Step7ProSim.Interfaces" fullword ascii
		$s2 = "payloadExecutionTimeInMilliSeconds" fullword ascii
		$s3 = "PackagingModule.Step7ProSim.dll" fullword wide
		$s4 = "<KillProcess>b__0" fullword ascii
		$s5 = "newDllFilename" fullword ascii
		$s6 = "PackagingModule.exe" fullword wide
		$s7 = "$863d8af0-cee6-4676-96ad-13e8540f4d47" fullword ascii
		$s8 = "RunPlcSim" fullword ascii
		$s9 = "$ccc64bc5-ef95-4217-adc4-5bf0d448c272" fullword ascii
		$s10 = "InstallProxy" fullword ascii
		$s11 = "DllProxyInstaller" fullword ascii
		$s12 = "FindFileInDrive" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and ($x1 or 3 of ($s*))) or (6 of them )
}
