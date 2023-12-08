import "pe"

rule apt_RU_Turla_Kazuar_DebugView_peFeatures
{
	meta:
		description = "Turla mimicking SysInternals Tools- peFeatures"
		reference = "https://www.epicturla.com/blog/sysinturla"
		version = "2.0"
		author = "JAG-S"
		score = 85
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and (pe.version_info["LegalCopyright"]=="Test Copyright" and ((pe.version_info["ProductName"]=="Sysinternals DebugView" and pe.version_info["Description"]=="Sysinternals DebugView") or (pe.version_info["FileVersion"]=="4.80.0.0" and pe.version_info["Comments"]=="Sysinternals DebugView") or (pe.version_info["OriginalName"] contains "DebugView.exe" and pe.version_info["InternalName"] contains "DebugView.exe") or (pe.version_info["OriginalName"]=="Agent.exe" and pe.version_info["InternalName"]=="Agent.exe")))
}
