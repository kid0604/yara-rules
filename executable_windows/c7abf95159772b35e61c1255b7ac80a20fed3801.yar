import "pe"

rule APT_RANCOR_PLAINTEE_Malware_Exports
{
	meta:
		description = "Detects PLAINTEE malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
		date = "2018-06-26"
		hash1 = "c35609822e6239934606a99cb3dbc925f4768f0b0654d6a2adc35eca473c505d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.exports("Add") and pe.exports("Sub") and pe.exports("DllEntryPoint") and pe.number_of_exports==3
}
