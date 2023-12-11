import "pe"

rule MALWARE_Win_RomCom_Loader
{
	meta:
		author = "ditekShen"
		description = "Hunt for RomCom loader"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and (pe.exports("DllCanUnloadNow") and pe.exports("DllGetClassObject") and pe.exports("DllRegisterServer") and pe.exports("DllUnregisterServer") and pe.exports("GetProxyDllInfo")) and for any fn in pe.export_details : (fn.forward_name contains "Dll")
}
